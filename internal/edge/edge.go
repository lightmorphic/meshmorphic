// Package edge implements the MeshMorphic ingress node.
//
// An edge is the only component on the traffic path, and it is built to be
// worthless to whoever takes it over. It accepts a visitor's TCP connection,
// reads the hostname out of the unencrypted ClientHello, and copies bytes.
// It holds no certificate, no certificate private key, and no ability to
// complete a TLS handshake with the visitor. The TLS session runs end to end
// between the visitor's browser and the home server, and the edge forwards
// ciphertext it cannot read.
//
// It also holds no routing authority. When an agent asks to serve a hostname
// under the mesh domain, the edge does not consult a register or check a
// credential — it recomputes the hostname from the public key the agent just
// proved it holds, and compares. Authorisation is arithmetic. There is
// nothing here for an attacker to forge and nothing for them to steal.
//
// What a compromised edge can see: hostnames, visitor IP addresses,
// timestamps, and ciphertext. What it can do: refuse to pass traffic, or
// present a certificate it does not have the key for, which every browser
// rejects loudly. It cannot serve a site in someone else's place, and it
// cannot reach into a home server, because no home server accepts an inbound
// connection.
package edge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
	"github.com/FOSSCharlie/meshmorphic/internal/proto"
	"github.com/FOSSCharlie/meshmorphic/internal/sni"
	"github.com/FOSSCharlie/meshmorphic/internal/transport"
)

// Config configures an edge.
type Config struct {
	// TunnelListen is the UDP address agents dial for their QUIC tunnel.
	TunnelListen string
	// HTTPSListen is the TCP address for visitor TLS traffic, normally :443.
	HTTPSListen string
	// HTTPListen is the TCP address for cleartext traffic, normally :80. It
	// carries ACME challenges and the redirect to HTTPS, both answered by the
	// home server rather than here.
	HTTPListen string
	// MeshDomains are the suffixes whose labels are key-derived and therefore
	// self-authorising, for example "awwe.uk". More than one is supported so
	// the network can add domains over time, and so a domain can be retired
	// without stranding the peers using it.
	MeshDomains []string
	// AllowCustomDomains permits agents to claim hostnames outside MeshDomain.
	// Such a claim is first-come, which is safe because DNS for that name must
	// already point here — and only the domain's owner controls that.
	AllowCustomDomains bool
	// Identity is this edge's keypair.
	Identity *identity.Identity
	// Logger receives operational logs.
	Logger *slog.Logger
}

// route is one hostname's destination.
type route struct {
	conn   transport.Conn
	peerID string
	// owner distinguishes registrations so a departing agent only withdraws
	// its own routes, never one that replaced it.
	owner *tunnel
}

// tunnel is one connected agent.
type tunnel struct {
	conn   transport.Conn
	peerID string
	pubKey []byte
	since  time.Time
}

// Server is a running edge.
type Server struct {
	cfg Config
	log *slog.Logger

	mu     sync.RWMutex
	routes map[string]route
}

// New creates an edge server.
func New(cfg Config) (*Server, error) {
	if cfg.Identity == nil {
		return nil, errors.New("edge: no identity")
	}
	if len(cfg.MeshDomains) == 0 {
		return nil, errors.New("edge: no mesh domains configured")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	for i, d := range cfg.MeshDomains {
		cfg.MeshDomains[i] = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
	}
	return &Server{cfg: cfg, log: cfg.Logger, routes: make(map[string]route)}, nil
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	tun, err := transport.Listen(s.cfg.TunnelListen, s.cfg.Identity)
	if err != nil {
		return err
	}
	defer func() { _ = tun.Close() }()

	https, err := net.Listen("tcp", s.cfg.HTTPSListen)
	if err != nil {
		return fmt.Errorf("edge: listen https: %w", err)
	}
	defer func() { _ = https.Close() }()

	plain, err := net.Listen("tcp", s.cfg.HTTPListen)
	if err != nil {
		return fmt.Errorf("edge: listen http: %w", err)
	}
	defer func() { _ = plain.Close() }()

	s.log.Info("edge listening",
		"tunnel", tun.Addr().String(),
		"https", https.Addr().String(),
		"http", plain.Addr().String(),
		"edge_id", s.cfg.Identity.ID(),
		"pubkey", identity.EncodeKey(s.cfg.Identity.PublicKey),
		"mesh_domains", strings.Join(s.cfg.MeshDomains, ","))

	go func() {
		<-ctx.Done()
		_ = tun.Close()
		_ = https.Close()
		_ = plain.Close()
	}()

	errc := make(chan error, 3)
	go func() { errc <- s.acceptTunnels(ctx, tun) }()
	go func() { errc <- s.acceptVisitors(ctx, https, proto.ProtoTLS) }()
	go func() { errc <- s.acceptVisitors(ctx, plain, proto.ProtoHTTP) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// acceptTunnels handles agents connecting inbound to establish their tunnel.
func (s *Server) acceptTunnels(ctx context.Context, ln *transport.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveTunnel(ctx, conn)
	}
}

// serveTunnel authenticates an agent and holds its routes for as long as it
// stays connected.
func (s *Server) serveTunnel(ctx context.Context, conn transport.Conn) {
	defer func() { _ = conn.Close("closing") }()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	peer, err := transport.ServerHandshake(stream, s.cfg.Identity)
	if err != nil {
		s.log.Debug("tunnel handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	if peer.Role != proto.RoleAgent {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrProtocol, "only agents may open a tunnel"))
		return
	}

	tun := &tunnel{conn: conn, peerID: peer.PeerID, pubKey: peer.PubKey, since: time.Now()}
	defer s.withdrawAll(tun)

	if err := proto.WriteFrame(stream, proto.Welcome{
		Type:     proto.TypeWelcome,
		PeerID:   peer.PeerID,
		ServerID: s.cfg.Identity.ID(),
	}); err != nil {
		return
	}

	for {
		typ, body, err := proto.ReadTyped(stream)
		if err != nil {
			return
		}
		switch typ {
		case proto.TypeClaim:
			var c proto.Claim
			if err := proto.Decode(body, &c); err != nil {
				return
			}
			accepted, rejected := s.claim(tun, c.Hostnames)
			for _, r := range rejected {
				s.log.Warn("claim refused", "peer", peer.PeerID, "host", r.host, "reason", r.reason)
			}
			if len(accepted) == 0 {
				if err := proto.WriteFrame(stream, proto.Errorf(proto.ErrHostNotAllowed,
					"no requested hostname could be served by this edge")); err != nil {
					return
				}
				continue
			}
			s.log.Info("routes claimed", "peer", peer.PeerID, "hostnames", accepted)
			if err := proto.WriteFrame(stream, proto.Claimed{Type: proto.TypeClaimed, Hostnames: accepted}); err != nil {
				return
			}
		case proto.TypePing:
			var p proto.Ping
			if err := proto.Decode(body, &p); err != nil {
				return
			}
			if err := proto.WriteFrame(stream, proto.Pong{Type: proto.TypePong, Seq: p.Seq}); err != nil {
				return
			}
		default:
			s.log.Debug("ignoring unknown message", "type", typ)
		}
	}
}

type rejection struct{ host, reason string }

// claim applies the edge's routing policy to a set of requested hostnames.
func (s *Server) claim(tun *tunnel, hostnames []string) (accepted []string, rejected []rejection) {
	for _, raw := range hostnames {
		host := normalizeHost(raw)
		if host == "" {
			rejected = append(rejected, rejection{raw, "empty hostname"})
			continue
		}
		if err := s.authorize(tun, host); err != nil {
			rejected = append(rejected, rejection{host, err.Error()})
			continue
		}
		s.mu.Lock()
		s.routes[host] = route{conn: tun.conn, peerID: tun.peerID, owner: tun}
		s.mu.Unlock()
		accepted = append(accepted, host)
	}
	return accepted, rejected
}

// authorize decides whether a peer may serve a hostname.
//
// For the mesh domain the answer is a calculation: the label must be the one
// this peer's public key produces. No register is consulted because none
// exists, and no gateway is asked because a gateway has no say. Forging a
// claim would mean finding a key whose hash lands on somebody else's label.
//
// Outside the mesh domain the edge cannot know who owns a name, so it does not
// pretend to. It takes the first claimant. That is safe because a claim is
// only worth anything if DNS for the name already points at this edge, and
// only the domain's owner can arrange that — and because a squatter still has
// no certificate for the name, so browsers refuse the connection rather than
// being deceived by it.
func (s *Server) authorize(tun *tunnel, host string) error {
	for _, domain := range s.cfg.MeshDomains {
		suffix := "." + domain
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		label := strings.TrimSuffix(host, suffix)
		if strings.Contains(label, ".") {
			return errors.New("mesh hostnames have exactly one label")
		}
		if !identity.VerifyHostLabel(label, tun.pubKey) {
			return errors.New("label is not the one this key derives")
		}
		return nil
	}
	if !s.cfg.AllowCustomDomains {
		return fmt.Errorf("this edge only serves names under %s", strings.Join(s.cfg.MeshDomains, ", "))
	}
	s.mu.RLock()
	existing, taken := s.routes[host]
	s.mu.RUnlock()
	if taken && existing.peerID != tun.peerID {
		return fmt.Errorf("already served by %s", existing.peerID)
	}
	return nil
}

// withdrawAll removes every route belonging to a departing tunnel.
func (s *Server) withdrawAll(tun *tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for host, r := range s.routes {
		// Compare the owner, not the peer ID: if the same peer reconnected and
		// re-claimed, the new tunnel owns the route and must not lose it when
		// the old one finishes tearing down.
		if r.owner == tun {
			delete(s.routes, host)
		}
	}
}

// lookup finds the tunnel serving a hostname.
func (s *Server) lookup(host string) (route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.routes[host]
	return r, ok
}

// acceptVisitors handles ordinary TCP connections from the internet.
func (s *Server) acceptVisitors(ctx context.Context, ln net.Listener, kind string) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// One rejected connection is not a reason to stop serving.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.serveVisitor(ctx, conn, kind)
	}
}

// serveVisitor routes one visitor connection into the mesh.
func (s *Server) serveVisitor(ctx context.Context, conn net.Conn, kind string) {
	defer func() { _ = conn.Close() }()

	var host string
	var replay []byte
	var err error

	switch kind {
	case proto.ProtoTLS:
		// Only the ClientHello is read, and only far enough to find the name.
		// Everything after this point is ciphertext to us.
		host, replay, err = sni.Peek(conn)
	case proto.ProtoHTTP:
		host, replay, err = peekHTTPHost(conn)
	}
	if err != nil {
		s.log.Debug("could not classify visitor connection",
			"remote", conn.RemoteAddr().String(), "kind", kind, "error", err)
		return
	}

	host = normalizeHost(host)
	r, ok := s.lookup(host)
	if !ok {
		s.log.Debug("no route", "host", host, "remote", conn.RemoteAddr().String())
		if kind == proto.ProtoHTTP {
			writeHTTPError(conn, 502, "This MeshMorphic site is not currently connected.")
		}
		return
	}

	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	stream, err := r.conn.OpenStream(openCtx)
	cancel()
	if err != nil {
		s.log.Warn("could not open tunnel stream", "host", host, "peer", r.peerID, "error", err)
		if kind == proto.ProtoHTTP {
			writeHTTPError(conn, 502, "This MeshMorphic site is not currently reachable.")
		}
		return
	}
	defer func() { _ = stream.Close() }()

	if err := proto.WriteFrame(stream, proto.Open{
		Type:   proto.TypeOpen,
		Proto:  kind,
		Host:   host,
		Remote: conn.RemoteAddr().String(),
	}); err != nil {
		return
	}
	// The bytes already read are replayed first, so the home server sees the
	// exact request the visitor sent, unaltered and in order.
	if len(replay) > 0 {
		if _, err := stream.Write(replay); err != nil {
			return
		}
	}
	splice(conn, stream)
}

// splice copies in both directions until either side finishes.
//
// The visitor->stream direction closes the stream's write side on completion,
// so the home server sees a clean end of request rather than a hang.
func splice(visitor net.Conn, stream transport.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, visitor)
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(visitor, stream)
		// Unblock the other direction if the visitor has stopped reading.
		if tc, ok := visitor.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// maxHTTPHead caps how much of a cleartext request is read while looking for
// the Host header, so an unauthenticated stranger cannot make the edge buffer
// without limit.
const maxHTTPHead = 8 << 10

// peekHTTPHost reads a cleartext request far enough to find its Host header,
// returning every byte consumed for replay.
func peekHTTPHost(conn net.Conn) (string, []byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(sni.PeekTimeout)); err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for len(buf) < maxHTTPHead {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
				host, herr := hostFromHead(buf[:i])
				return host, buf, herr
			}
		}
		if err != nil {
			return "", buf, fmt.Errorf("edge: read request head: %w", err)
		}
	}
	return "", buf, errors.New("edge: request head exceeded the size limit")
}

// hostFromHead extracts the Host header from request head bytes.
func hostFromHead(head []byte) (string, error) {
	lines := strings.Split(string(head), "\r\n")
	for _, line := range lines[1:] { // skip the request line
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "host") {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errors.New("edge: request has no Host header")
}

// writeHTTPError sends a plain response to a cleartext visitor.
//
// Kept deliberately bland: it must not name the peer, the mesh, or anything
// about who was meant to be here, because that is information an edge should
// not be handing to whoever asks.
func writeHTTPError(conn net.Conn, code int, msg string) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	body := msg + "\n"
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", code, statusText(code), len(body), body)
}

func statusText(code int) string {
	switch code {
	case 502:
		return "Bad Gateway"
	case 404:
		return "Not Found"
	default:
		return "Error"
	}
}

// normalizeHost lowercases a hostname and strips a trailing dot and any port,
// so an SNI value and a Host header are compared on the same footing.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		if isAllDigits(h[i+1:]) {
			h = h[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Stats reports aggregate counts for monitoring, with no identities in it.
type Stats struct {
	Routes int `json:"routes"`
}

// Stats returns current counts.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Routes: len(s.routes)}
}
