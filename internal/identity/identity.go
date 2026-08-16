// Package identity handles MeshMorphic peer identities.
//
// A peer is an Ed25519 keypair. Its ID is derived from its public key, so an
// ID and a key can be checked against each other without asking any authority
// whether they belong together.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Prefix marks a MeshMorphic peer ID and its identity-derivation version.
const Prefix = "mm1"

// zBase32 is Zooko's base32: no 0/1/l/v, chosen so IDs survive being read
// aloud, written down, and typed back in by someone who is not concentrating.
const zBase32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

// ErrNoIdentity is returned when an identity file does not exist yet.
var ErrNoIdentity = errors.New("identity: no identity file")

// Identity is a peer's keypair.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

type identityFile struct {
	Version    int    `json:"version"`
	PeerID     string `json:"peer_id"`
	PrivateKey string `json:"private_key"` // base64, seed+public as Go stores it
	Comment    string `json:"comment"`
}

// Generate creates a new random identity.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate: %w", err)
	}
	return &Identity{PrivateKey: priv, PublicKey: pub}, nil
}

// ID returns the peer ID derived from the public key.
func (id *Identity) ID() string { return IDFromPublicKey(id.PublicKey) }

// Sign signs a message with the identity key.
func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(id.PrivateKey, msg)
}

// IDFromPublicKey derives the self-certifying peer ID for a public key.
//
// Twenty bytes of SHA-256 gives 160 bits, which is a 32-character ID — short
// enough to appear in a URL or be read down a phone line, long enough that
// searching for a collision is not a thing anyone will do.
func IDFromPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return Prefix + encodeZBase32(sum[:20])
}

// hostLabelDomain separates the hostname derivation from the peer-ID
// derivation, so the two can never be confused for one another and neither
// constrains the other's future.
const hostLabelDomain = "meshmorphic-host-v1"

// HostLabel derives the DNS label a peer is entitled to serve, from its public
// key alone.
//
// This is the mechanism that lets a gateway hold nothing. There is no name
// registry to consult and no authority to ask: an edge decides whether a peer
// may answer for a hostname by recomputing this function and comparing. A peer
// can only claim the one label its key produces, and producing a key that maps
// to somebody else's label means finding a 96-bit second preimage.
//
// Ninety-six bits rather than the full hash keeps the label short enough to
// read aloud, while leaving forgery far outside what anyone can compute.
func HostLabel(pub ed25519.PublicKey) string {
	h := sha256.New()
	h.Write([]byte(hostLabelDomain))
	h.Write([]byte{0})
	h.Write(pub)
	return encodeZBase32(h.Sum(nil)[:12])
}

// VerifyHostLabel reports whether label is the one pub is entitled to.
func VerifyHostLabel(label string, pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return strings.EqualFold(label, HostLabel(pub))
}

// VerifyID reports whether id is genuinely the ID of pub. Servers call this
// before trusting a claimed pairing, which is what makes identity
// self-certifying rather than merely asserted.
func VerifyID(id string, pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	// Constant time is not required: both sides are public values.
	return id == IDFromPublicKey(pub)
}

// encodeZBase32 encodes bytes as z-base-32 with no padding.
func encodeZBase32(b []byte) string {
	var sb strings.Builder
	var buf, bits uint
	for _, c := range b {
		buf = buf<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(zBase32[(buf>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(zBase32[(buf<<(5-bits))&31])
	}
	return sb.String()
}

// EncodeKey renders a public key as base64, the form used on the wire and in
// configuration files.
func EncodeKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodeKey parses a base64 public key, rejecting anything of the wrong size
// rather than letting a truncated key through to a signature check.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("identity: decode key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: decode key: got %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Load reads an identity from disk.
func Load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	var f identityFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	priv, err := base64.StdEncoding.DecodeString(f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("identity: decode private key in %s: %w", path, err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity: private key in %s is %d bytes, want %d", path, len(priv), ed25519.PrivateKeySize)
	}
	id := &Identity{
		PrivateKey: ed25519.PrivateKey(priv),
		PublicKey:  ed25519.PrivateKey(priv).Public().(ed25519.PublicKey),
	}
	// A file whose recorded ID disagrees with its key means the file was
	// edited or corrupted. Better to stop than to run under a wrong name.
	if f.PeerID != "" && f.PeerID != id.ID() {
		return nil, fmt.Errorf("identity: %s claims %s but its key derives %s", path, f.PeerID, id.ID())
	}
	return id, nil
}

// Save writes an identity to disk with owner-only permissions.
func Save(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: create dir for %s: %w", path, err)
	}
	f := identityFile{
		Version:    1,
		PeerID:     id.ID(),
		PrivateKey: base64.StdEncoding.EncodeToString(id.PrivateKey),
		Comment:    "MeshMorphic private identity. Anyone holding this file can act as this peer. Do not share it.",
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: encode: %w", err)
	}
	// Write-then-rename so a crash mid-write cannot leave a half identity that
	// would lose the peer its name on next start.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: rename %s: %w", tmp, err)
	}
	return nil
}

// LoadOrCreate returns the identity at path, generating and saving one if
// there is none. The bool reports whether a new identity was created.
func LoadOrCreate(path string) (*Identity, bool, error) {
	id, err := Load(path)
	switch {
	case err == nil:
		return id, false, nil
	case errors.Is(err, ErrNoIdentity):
		id, err := Generate()
		if err != nil {
			return nil, false, err
		}
		if err := Save(path, id); err != nil {
			return nil, false, err
		}
		return id, true, nil
	default:
		return nil, false, err
	}
}
