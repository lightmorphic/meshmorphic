package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Device pairing exists because "local network only" is a weaker boundary than
// it sounds. A home network holds guests, a smart television, a printer that
// was last updated in 2019, and whatever a child installed. Leaving a panel
// that can replace the website open to all of them would undo much of the work
// the rest of this system does.
//
// The design goal is a real authentication boundary that costs the user no
// setup: no password to invent, nothing to remember, nothing to lose.
//
//   - The first browser to open the panel becomes the owner. On a freshly
//     installed machine that is the person standing in front of it.
//   - Every later device must be approved, either from a browser already
//     enrolled or by running a command on the machine itself. Both require
//     access somebody on the guest wi-fi does not have.
//
// Tokens are stored hashed, so the state file is not itself a set of keys to
// the panel.

// DeviceRecord is one enrolled browser.
type DeviceRecord struct {
	// TokenHash is the SHA-256 of the cookie value, hex encoded. The token
	// itself is never written to disk.
	TokenHash string `json:"token_hash"`
	Name      string `json:"name"`
	Added     int64  `json:"added"`
	LastSeen  int64  `json:"last_seen"`
}

// pendingRequest is a device waiting to be let in.
type pendingRequest struct {
	Code    string
	Name    string
	Token   string
	Created time.Time
}

// deviceStore holds enrolled devices and pending approvals.
type deviceStore struct {
	mu      sync.Mutex
	path    string
	devices []DeviceRecord
	pending map[string]*pendingRequest // keyed by approval code
}

type deviceFile struct {
	Version int            `json:"version"`
	Devices []DeviceRecord `json:"devices"`
}

// pendingTTL bounds how long an approval code stays usable.
const pendingTTL = 10 * time.Minute

func openDeviceStore(path string) (*deviceStore, error) {
	s := &deviceStore{path: path, pending: make(map[string]*pendingRequest)}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("panel: read devices: %w", err)
	}
	var f deviceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("panel: parse devices: %w", err)
	}
	s.devices = f.Devices
	return s, nil
}

// saveLocked persists the device list. The caller must hold the lock.
func (s *deviceStore) saveLocked() error {
	raw, err := json.MarshalIndent(deviceFile{Version: 1, Devices: s.devices}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// hashToken hashes a cookie value for storage and comparison.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newToken mints a device cookie value.
func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// newCode mints a short numeric approval code, the kind a person can read off
// one screen and type into another.
func newCode() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	n := (uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

// Empty reports whether no device has been enrolled yet.
func (s *deviceStore) Empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.devices) == 0
}

// Verify checks a cookie value against the enrolled devices.
func (s *deviceStore) Verify(token string) bool {
	if token == "" {
		return false
	}
	want := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.devices {
		// Constant-time compare: this value decides access, and a timing
		// oracle on it would leak the stored hash byte by byte.
		if subtle.ConstantTimeCompare([]byte(s.devices[i].TokenHash), []byte(want)) == 1 {
			s.devices[i].LastSeen = time.Now().Unix()
			return true
		}
	}
	return false
}

// Enroll adds a device and returns its token.
func (s *deviceStore) Enroll(name string) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	s.devices = append(s.devices, DeviceRecord{
		TokenHash: hashToken(token),
		Name:      name,
		Added:     now,
		LastSeen:  now,
	})
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return token, nil
}

// RequestAccess registers a device waiting for approval and returns its code.
func (s *deviceStore) RequestAccess(name string) (*pendingRequest, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	code, err := newCode()
	if err != nil {
		return nil, err
	}
	req := &pendingRequest{Code: code, Name: name, Token: token, Created: time.Now()}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	// A cap stops an attacker on the network filling the approval list with
	// noise so the real request is impossible to pick out.
	if len(s.pending) >= 10 {
		return nil, errors.New("panel: too many devices are already waiting for approval")
	}
	s.pending[code] = req
	return req, nil
}

// expireLocked drops stale requests. The caller must hold the lock.
func (s *deviceStore) expireLocked() {
	for code, req := range s.pending {
		if time.Since(req.Created) > pendingTTL {
			delete(s.pending, code)
		}
	}
}

// Pending lists devices awaiting approval.
func (s *deviceStore) Pending() []pendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	out := make([]pendingRequest, 0, len(s.pending))
	for _, req := range s.pending {
		// The token is deliberately not copied out: nothing that renders a
		// page needs it, and it must not end up in HTML.
		out = append(out, pendingRequest{Code: req.Code, Name: req.Name, Created: req.Created})
	}
	return out
}

// Approve enrolls a pending device by its code.
func (s *deviceStore) Approve(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	req, ok := s.pending[code]
	if !ok {
		return errors.New("panel: that approval code is not valid or has expired")
	}
	delete(s.pending, code)
	now := time.Now().Unix()
	s.devices = append(s.devices, DeviceRecord{
		TokenHash: hashToken(req.Token),
		Name:      req.Name,
		Added:     now,
		LastSeen:  now,
	})
	return s.saveLocked()
}

// Approved reports whether a pending token has since been approved, which is
// how the waiting browser learns it may proceed.
func (s *deviceStore) Approved(token string) bool { return s.Verify(token) }

// Devices lists enrolled devices.
func (s *deviceStore) Devices() []DeviceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DeviceRecord, len(s.devices))
	copy(out, s.devices)
	for i := range out {
		// The hash is an internal detail and is not shown; truncating it here
		// keeps it out of any template that might later render the struct.
		out[i].TokenHash = out[i].TokenHash[:8]
	}
	return out
}

// Revoke removes a device by the visible prefix of its hash.
func (s *deviceStore) Revoke(prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.devices {
		if len(s.devices[i].TokenHash) >= 8 && s.devices[i].TokenHash[:8] == prefix {
			s.devices = append(s.devices[:i], s.devices[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("panel: no such device")
}

// deviceCookie is the cookie carrying a device token.
const deviceCookie = "mm_device"

// setDeviceCookie writes the device token cookie.
//
// Secure is deliberately not set: the panel is served over plain HTTP on the
// local network, where there is no certificate to use and no certificate
// authority that would issue one for a private address. SameSite=Strict and
// HttpOnly do the work that matters here, and the origin checks in
// requireSameOrigin close what remains.
func setDeviceCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((365 * 24 * time.Hour).Seconds()),
	})
}

// deviceToken reads the token from a request.
func deviceToken(r *http.Request) string {
	c, err := r.Cookie(deviceCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
