// Package proto defines the MeshMorphic v1 wire protocol: message types and
// the length-prefixed JSON framing they travel in.
//
// JSON on the control plane is a deliberate choice. These messages are sent a
// handful of times an hour, and the people this project is for need to be able
// to point tcpdump at it and understand what their own machine is saying.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version this build speaks.
const Version = 1

// ALPN is the QUIC application protocol identifier.
const ALPN = "meshmorphic/1"

// MaxFrame caps a single control frame. Control messages are small; anything
// approaching this is a bug or an attempt to make us allocate.
const MaxFrame = 1 << 20 // 1 MiB

// Message types.
const (
	TypeHello     = "hello"
	TypeChallenge = "challenge"
	TypeAuth      = "auth"
	TypeWelcome   = "welcome"
	TypeAnnounce  = "announce"
	TypePing      = "ping"
	TypePong      = "pong"
	TypeEdges     = "edges"
	TypeGateways  = "gateways"
	TypeClaim     = "claim"
	TypeClaimed   = "claimed"
	TypeOpen      = "open"
	TypeError     = "error"
)

// Roles a peer can present at handshake.
const (
	RoleAgent   = "agent"
	RoleEdge    = "edge"
	RoleGateway = "gateway"
)

// Tunnel protocols carried on a data stream.
const (
	ProtoTLS  = "tls"
	ProtoHTTP = "http"
)

// Error codes. Stable strings so operators can grep logs.
const (
	ErrUnsupportedVersion = "unsupported_version"
	ErrBadIdentity        = "bad_identity"
	ErrBadSignature       = "bad_signature"
	ErrHostNotAllowed     = "host_not_allowed"
	ErrNoRoute            = "no_route"
	ErrInternal           = "internal"
	ErrProtocol           = "protocol"
)

// Envelope is the common shape every control message shares. Messages are
// decoded twice: once to read the type, once into the concrete struct.
type Envelope struct {
	Type string `json:"type"`
}

// Hello opens a control stream.
type Hello struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	PeerID  string `json:"peer_id"`
	PubKey  string `json:"pubkey"` // base64 Ed25519
	Role    string `json:"role"`
	Agent   string `json:"agent,omitempty"` // software version, for diagnostics
}

// Challenge carries the server's random nonce.
type Challenge struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"` // base64, 32 bytes
	// ServerPubKey lets the client confirm the key it pinned at the TLS layer
	// is the same one it is about to bind its signature to.
	ServerPubKey string `json:"server_pubkey"`
}

// Auth answers a Challenge.
type Auth struct {
	Type string `json:"type"`
	Sig  string `json:"sig"` // base64 Ed25519 signature
}

// EdgeInfo describes an edge the agent may connect to. Public keys are learned
// only here, inside an authenticated session, which is what makes pinning them
// meaningful.
type EdgeInfo struct {
	EdgeID string `json:"edge_id"`
	PubKey string `json:"pubkey"`
	Addr   string `json:"addr"` // host:port for the QUIC tunnel listener
}

// GatewayInfo describes another gateway. Gateways gossip these so that an
// agent which reached any one gateway learns about the rest, and the network
// does not depend on a published list that somebody has to maintain.
//
// This gossip needs no authentication, which is a consequence of the design
// rather than an oversight: a gateway holds no state and no authority, so the
// worst a fabricated entry can do is waste one dial attempt.
type GatewayInfo struct {
	GatewayID string `json:"gateway_id"`
	PubKey    string `json:"pubkey"`
	Addr      string `json:"addr"`
}

// Welcome completes a successful handshake.
//
// Note what is absent: no assigned name, no credential, no token. The gateway
// grants the agent nothing, because it has nothing to grant. HostLabel and
// Nickname are both computed from the agent's own public key, and are echoed
// back only so the agent can confirm the two sides agree.
type Welcome struct {
	Type      string        `json:"type"`
	PeerID    string        `json:"peer_id"`
	HostLabel string        `json:"host_label,omitempty"` // derived from the peer's key
	Nickname  string        `json:"nickname,omitempty"`   // cosmetic, also derived
	Hostnames []string      `json:"hostnames,omitempty"`  // fully qualified
	Edges     []EdgeInfo    `json:"edges,omitempty"`
	Gateways  []GatewayInfo `json:"gateways,omitempty"`
	ServerID  string        `json:"server_id,omitempty"`
}

// Announce reports what the agent can currently be reached at. Endpoints are
// unused in Phase 1 (all traffic goes via an edge) but are part of the wire
// format from the start so that direct peer-to-peer paths in a later phase are
// an addition rather than a break.
type Announce struct {
	Type      string   `json:"type"`
	Endpoints []string `json:"endpoints,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}

// Ping and Pong keep the tunnel alive and let each side notice a dead peer.
type Ping struct {
	Type string `json:"type"`
	Seq  uint64 `json:"seq"`
}

// Pong answers a Ping.
type Pong struct {
	Type string `json:"type"`
	Seq  uint64 `json:"seq"`
}

// Edges pushes an updated edge list to a connected agent.
type Edges struct {
	Type  string     `json:"type"`
	Edges []EdgeInfo `json:"edges"`
}

// Gateways pushes an updated gateway list to a connected agent.
type Gateways struct {
	Type     string        `json:"type"`
	Gateways []GatewayInfo `json:"gateways"`
}

// Claim asks an edge to route hostnames to this connection.
//
// There is no credential attached, because there is no issuer. The connection
// has already proved which key the peer holds, and the edge decides what that
// key is entitled to by recomputing identity.HostLabel. Authorisation is
// arithmetic, not a permission somebody granted.
type Claim struct {
	Type      string   `json:"type"`
	Hostnames []string `json:"hostnames"`
}

// Claimed confirms which hostnames an edge accepted.
type Claimed struct {
	Type      string   `json:"type"`
	Hostnames []string `json:"hostnames"`
}

// Open is the single frame at the head of a data stream, before the stream
// becomes an opaque byte pipe.
type Open struct {
	Type   string `json:"type"`
	Proto  string `json:"proto"` // ProtoTLS or ProtoHTTP
	Host   string `json:"host"`
	Remote string `json:"remote"` // visitor address, for the agent's logs
}

// Error reports a failure. The receiver should treat the stream as finished.
type Error struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Errorf builds an Error message.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Type: TypeError, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Err renders an Error as a Go error so call sites can treat a remote refusal
// the same as a local failure.
func (e *Error) Err() error {
	if e.Message == "" {
		return fmt.Errorf("remote error: %s", e.Code)
	}
	return fmt.Errorf("remote error: %s: %s", e.Code, e.Message)
}

// ErrFrameTooLarge is returned when a peer announces an oversized frame.
var ErrFrameTooLarge = errors.New("proto: frame exceeds maximum size")

// WriteFrame encodes v as JSON and writes one length-prefixed frame.
func WriteFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: encode: %w", err)
	}
	if len(body) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(body)))
	copy(buf[4:], body)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("proto: write: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame and returns its raw JSON body.
//
// The length is checked before allocating, so a hostile peer cannot make us
// reserve a gigabyte by claiming it is about to send one.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err // io.EOF passed through unwrapped: callers test for it
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("proto: read body: %w", err)
	}
	return body, nil
}

// ReadTyped reads a frame and reports its type alongside the raw body, so the
// caller can dispatch and then decode into the right struct.
func ReadTyped(r io.Reader) (string, []byte, error) {
	body, err := ReadFrame(r)
	if err != nil {
		return "", nil, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", nil, fmt.Errorf("proto: decode envelope: %w", err)
	}
	if env.Type == "" {
		return "", nil, errors.New("proto: message has no type")
	}
	return env.Type, body, nil
}

// Decode unmarshals a raw frame body into v.
func Decode(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("proto: decode: %w", err)
	}
	return nil
}

// ReadExpect reads one frame, requires it to be of type want, and decodes it
// into v. A remote Error is returned as a Go error rather than a type mismatch,
// so failures surface with the reason the other side actually gave.
func ReadExpect(r io.Reader, want string, v any) error {
	typ, body, err := ReadTyped(r)
	if err != nil {
		return err
	}
	if typ == TypeError && want != TypeError {
		var e Error
		if err := Decode(body, &e); err != nil {
			return err
		}
		return e.Err()
	}
	if typ != want {
		return fmt.Errorf("proto: expected %q, got %q", want, typ)
	}
	return Decode(body, v)
}
