// Package transport carries the MeshMorphic control and data planes over QUIC.
//
// Two properties of QUIC are load-bearing here rather than incidental:
//
//   - Connection migration. A QUIC connection is keyed by a connection ID, not
//     by an IP/port pair, so when a home broadband connection changes address
//     the tunnel survives instead of dropping. That is the dynamic-IP problem
//     solved in the transport, which is where it belongs.
//   - Native stream multiplexing. Every visitor connection becomes a stream on
//     the one tunnel the agent already has open, so the home machine never
//     dials a second time and never listens at all.
//
// TLS here is not Web PKI. Each peer's certificate carries its Ed25519
// identity key, so "verify the certificate" and "check this is the peer I
// expected" are the same operation, with no certificate authority involved.
package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
	"github.com/FOSSCharlie/meshmorphic/internal/proto"
)

// AuthDomain separates handshake signatures from every other signature in the
// protocol.
const AuthDomain = "meshmorphic-auth-v1"

// Timeouts. Generous enough for a slow home link, short enough that a dead
// peer is noticed while someone is still looking at the page.
const (
	HandshakeTimeout = 15 * time.Second
	KeepAlivePeriod  = 20 * time.Second
	IdleTimeout      = 90 * time.Second
	DialTimeout      = 20 * time.Second
)

// SelfSignedTLS builds a TLS certificate whose key is the peer's identity key.
//
// The certificate fields are almost entirely ceremony: nothing validates the
// subject, the dates or the chain. The only field that carries meaning is the
// public key, which the other side compares against the identity it expected.
func SelfSignedTLS(id *identity.Identity) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id.ID()},
		NotBefore:    time.Now().Add(-time.Hour),
		// Long-lived on purpose: expiry is not the mechanism protecting this,
		// key pinning is, and a rotating cert would only create false alarms.
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.PublicKey, id.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: create certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  id.PrivateKey,
		Leaf:        tmpl,
	}, nil
}

// ServerTLS returns a TLS config for a peer accepting MeshMorphic connections.
func ServerTLS(id *identity.Identity) (*tls.Config, error) {
	cert, err := SelfSignedTLS(id)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{proto.ALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ErrWrongPeer means the peer presented a different identity than expected.
// This is the signal that something is intercepting the connection.
var ErrWrongPeer = errors.New("transport: peer identity does not match the expected key")

// ClientTLS returns a TLS config that accepts exactly one server identity.
//
// InsecureSkipVerify switches off Web PKI validation, which is correct here:
// there is no CA in this trust model, and the replacement check below is
// strictly stronger than a CA check would be. The connection succeeds only if
// the server proves possession of one specific key.
func ClientTLS(id *identity.Identity, expect ed25519.PublicKey) (*tls.Config, error) {
	cert, err := SelfSignedTLS(id)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{proto.ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("transport: peer sent no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("transport: parse peer certificate: %w", err)
			}
			got, ok := leaf.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("transport: peer certificate is not Ed25519")
			}
			if !got.Equal(expect) {
				return fmt.Errorf("%w: got %s, expected %s",
					ErrWrongPeer, identity.IDFromPublicKey(got), identity.IDFromPublicKey(expect))
			}
			return nil
		},
	}, nil
}

// QUICConfig returns the shared QUIC tuning.
func QUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  IdleTimeout,
		KeepAlivePeriod: KeepAlivePeriod,
		// Migration is the reason this project is on QUIC at all.
		DisablePathMTUDiscovery: false,
		Allow0RTT:               false,
		MaxIncomingStreams:      1024,
		MaxIncomingUniStreams:   0,
	}
}

// authInput builds the bytes signed during the handshake.
//
// Binding the server's own public key into the signature is what stops a
// hostile server from relaying a client's auth response to a third party and
// authenticating as that client.
func authInput(nonce []byte, serverPub ed25519.PublicKey) []byte {
	buf := make([]byte, 0, len(AuthDomain)+1+len(nonce)+1+len(serverPub))
	buf = append(buf, AuthDomain...)
	buf = append(buf, 0)
	buf = append(buf, nonce...)
	buf = append(buf, 0)
	buf = append(buf, serverPub...)
	return buf
}

// PeerInfo describes an authenticated remote peer.
type PeerInfo struct {
	PeerID string
	PubKey ed25519.PublicKey
	Role   string
	Agent  string
}

// ClientHandshake performs the client half of the authentication exchange on
// an already-open control stream.
func ClientHandshake(stream Stream, id *identity.Identity, role, agentVersion string, expectServer ed25519.PublicKey) error {
	if err := stream.SetDeadline(time.Now().Add(HandshakeTimeout)); err != nil {
		return fmt.Errorf("transport: set handshake deadline: %w", err)
	}
	// Clearing the deadline matters: the control stream stays open for the life
	// of the tunnel, and a lingering deadline would kill it mid-service.
	defer func() { _ = stream.SetDeadline(time.Time{}) }()

	hello := proto.Hello{
		Type:    proto.TypeHello,
		Version: proto.Version,
		PeerID:  id.ID(),
		PubKey:  identity.EncodeKey(id.PublicKey),
		Role:    role,
		Agent:   agentVersion,
	}
	if err := proto.WriteFrame(stream, hello); err != nil {
		return err
	}

	var ch proto.Challenge
	if err := proto.ReadExpect(stream, proto.TypeChallenge, &ch); err != nil {
		return err
	}
	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("transport: decode nonce: %w", err)
	}
	if len(nonce) < 32 {
		return errors.New("transport: server nonce is too short to be safe")
	}

	// The server states which key it is; confirm it is the one TLS pinned.
	// TLS has already enforced this, so a mismatch means the two layers
	// disagree and the safe response is to stop.
	srvPub, err := identity.DecodeKey(ch.ServerPubKey)
	if err != nil {
		return fmt.Errorf("transport: server key: %w", err)
	}
	if expectServer != nil && !srvPub.Equal(expectServer) {
		return fmt.Errorf("%w: challenge names a different key than the certificate", ErrWrongPeer)
	}

	sig := id.Sign(authInput(nonce, srvPub))
	return proto.WriteFrame(stream, proto.Auth{
		Type: proto.TypeAuth,
		Sig:  base64.StdEncoding.EncodeToString(sig),
	})
}

// ServerHandshake performs the server half of the authentication exchange and
// returns the authenticated peer.
//
// The caller sends the Welcome afterwards, because what belongs in it differs
// between the gateway and an edge.
func ServerHandshake(stream Stream, id *identity.Identity) (*PeerInfo, error) {
	if err := stream.SetDeadline(time.Now().Add(HandshakeTimeout)); err != nil {
		return nil, fmt.Errorf("transport: set handshake deadline: %w", err)
	}
	defer func() { _ = stream.SetDeadline(time.Time{}) }()

	var hello proto.Hello
	if err := proto.ReadExpect(stream, proto.TypeHello, &hello); err != nil {
		return nil, err
	}
	if hello.Version != proto.Version {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrUnsupportedVersion,
			"this server speaks protocol %d, you offered %d", proto.Version, hello.Version))
		return nil, fmt.Errorf("transport: unsupported protocol version %d", hello.Version)
	}
	pub, err := identity.DecodeKey(hello.PubKey)
	if err != nil {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrBadIdentity, "%v", err))
		return nil, err
	}
	// Self-certifying identity: the claimed ID must actually derive from the
	// claimed key. Checking this first removes any chance of the rest of the
	// system reasoning about a mismatched pair.
	if !identity.VerifyID(hello.PeerID, pub) {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrBadIdentity,
			"peer id %s does not derive from the supplied key", hello.PeerID))
		return nil, fmt.Errorf("transport: peer id %s does not match its key", hello.PeerID)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("transport: nonce: %w", err)
	}
	if err := proto.WriteFrame(stream, proto.Challenge{
		Type:         proto.TypeChallenge,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		ServerPubKey: identity.EncodeKey(id.PublicKey),
	}); err != nil {
		return nil, err
	}

	var auth proto.Auth
	if err := proto.ReadExpect(stream, proto.TypeAuth, &auth); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(auth.Sig)
	if err != nil {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrBadSignature, "%v", err))
		return nil, fmt.Errorf("transport: decode signature: %w", err)
	}
	if !ed25519.Verify(pub, authInput(nonce, id.PublicKey), sig) {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrBadSignature, "signature did not verify"))
		return nil, fmt.Errorf("transport: bad signature from %s", hello.PeerID)
	}

	return &PeerInfo{PeerID: hello.PeerID, PubKey: pub, Role: hello.Role, Agent: hello.Agent}, nil
}

// Dial opens an authenticated QUIC connection to a peer, pinned to expect.
func Dial(ctx context.Context, addr string, id *identity.Identity, expect ed25519.PublicKey) (Conn, error) {
	tlsConf, err := ClientTLS(id, expect)
	if err != nil {
		return Conn{}, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	qc, err := quic.DialAddr(dialCtx, addr, tlsConf, QUICConfig())
	if err != nil {
		return Conn{}, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	return Conn{qc}, nil
}

// Listen starts accepting authenticated QUIC connections.
func Listen(addr string, id *identity.Identity) (*Listener, error) {
	tlsConf, err := ServerTLS(id)
	if err != nil {
		return nil, err
	}
	ln, err := quic.ListenAddr(addr, tlsConf, QUICConfig())
	if err != nil {
		return nil, fmt.Errorf("transport: listen %s: %w", addr, err)
	}
	return &Listener{ln}, nil
}

// Listener accepts MeshMorphic connections.
type Listener struct{ ln *quic.Listener }

// Accept waits for the next connection.
func (l *Listener) Accept(ctx context.Context) (Conn, error) {
	qc, err := l.ln.Accept(ctx)
	if err != nil {
		return Conn{}, err
	}
	return Conn{qc}, nil
}

// Addr reports the local listening address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener.
func (l *Listener) Close() error { return l.ln.Close() }

// Conn is a MeshMorphic connection to one peer.
type Conn struct{ qc quic.Connection }

// Stream is one multiplexed stream: either the control stream or a data tunnel.
type Stream = quic.Stream

// OpenStream opens a new outbound stream.
func (c Conn) OpenStream(ctx context.Context) (Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("transport: open stream: %w", err)
	}
	return s, nil
}

// AcceptStream waits for the peer to open a stream.
func (c Conn) AcceptStream(ctx context.Context) (Stream, error) {
	return c.qc.AcceptStream(ctx)
}

// RemoteAddr reports the peer's current address. With connection migration
// this can change during the life of the connection, which is the point.
func (c Conn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

// LocalAddr reports the local address.
func (c Conn) LocalAddr() net.Addr { return c.qc.LocalAddr() }

// Context is cancelled when the connection ends.
func (c Conn) Context() context.Context { return c.qc.Context() }

// Close shuts the connection down with a reason the other side can log.
func (c Conn) Close(reason string) error {
	return c.qc.CloseWithError(0, reason)
}

// Valid reports whether the connection was produced by a successful dial or
// accept, as opposed to being the zero value returned alongside an error.
func (c Conn) Valid() bool { return c.qc != nil }

// streamConn adapts a QUIC stream to net.Conn.
//
// quic-go streams deliberately have no addresses of their own, but the code
// that consumes them — crypto/tls, net/http — insists on net.Conn. The
// addresses are borrowed from the underlying connection, which is what a
// caller asking "who is this" actually wants to know.
type streamConn struct {
	Stream
	local  net.Addr
	remote net.Addr
}

func (s streamConn) LocalAddr() net.Addr  { return s.local }
func (s streamConn) RemoteAddr() net.Addr { return s.remote }

// Close shuts both directions down. A bare Stream.Close only closes the send
// side, which would leave a TLS server waiting for a peer that has gone.
func (s streamConn) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

// NetConn wraps a stream as a net.Conn using the connection's addresses.
func (c Conn) NetConn(s Stream) net.Conn {
	return streamConn{Stream: s, local: c.LocalAddr(), remote: c.RemoteAddr()}
}

// NetConnWithRemote wraps a stream as a net.Conn reporting a specific remote
// address, so the agent's HTTP server logs the visitor rather than the edge.
func (c Conn) NetConnWithRemote(s Stream, remote net.Addr) net.Conn {
	if remote == nil {
		remote = c.RemoteAddr()
	}
	return streamConn{Stream: s, local: c.LocalAddr(), remote: remote}
}
