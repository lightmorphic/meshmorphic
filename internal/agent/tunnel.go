package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/proto"
	"github.com/lightmorphic/meshmorphic/internal/transport"
	"github.com/lightmorphic/meshmorphic/internal/version"
)

// superviseEdge keeps one edge tunnel alive until its context is cancelled.
//
// The agent connects to every edge it is told about, not just one. That is the
// failover mechanism in its entirety: DNS hands visitors whichever edge it
// likes, and all of them already have a live tunnel to this machine. An edge
// disappearing costs the visitors currently mid-request on it and nothing more.
func (a *Agent) superviseEdge(ctx context.Context, info proto.EdgeInfo) {
	pub, err := identity.DecodeKey(info.PubKey)
	if err != nil {
		a.log.Warn("edge has an unusable public key, ignoring", "edge", info.EdgeID, "error", err)
		return
	}
	// The ID must derive from the key. A gateway that sends a mismatched pair
	// is either broken or trying something; either way this agent stops here.
	if !identity.VerifyID(info.EdgeID, pub) {
		a.log.Warn("edge id does not match its key, refusing", "edge", info.EdgeID)
		return
	}

	backoff := time.Second
	const maxBackoff = time.Minute

	for ctx.Err() == nil {
		err := a.runEdgeTunnel(ctx, info, pub)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.log.Warn("edge tunnel ended", "edge", info.EdgeID, "addr", info.Addr, "error", err)
		}
		a.markEdgeDown(info.EdgeID)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runEdgeTunnel holds one tunnel until it fails.
func (a *Agent) runEdgeTunnel(ctx context.Context, info proto.EdgeInfo, pub []byte) error {
	conn, err := transport.Dial(ctx, info.Addr, a.cfg.Identity, pub)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close("closing") }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	if err := transport.ClientHandshake(stream, a.cfg.Identity, proto.RoleAgent, version.Version, pub); err != nil {
		return fmt.Errorf("agent: handshake with edge %s: %w", info.Addr, err)
	}
	var welcome proto.Welcome
	if err := proto.ReadExpect(stream, proto.TypeWelcome, &welcome); err != nil {
		return err
	}

	hostnames := a.hostnameList()
	if len(hostnames) == 0 {
		return errors.New("agent: no hostnames to claim")
	}
	if err := proto.WriteFrame(stream, proto.Claim{Type: proto.TypeClaim, Hostnames: hostnames}); err != nil {
		return err
	}
	var claimed proto.Claimed
	if err := proto.ReadExpect(stream, proto.TypeClaimed, &claimed); err != nil {
		return err
	}
	a.log.Info("tunnel established", "edge", info.EdgeID, "addr", info.Addr, "serving", claimed.Hostnames)
	a.markEdgeUp(info.EdgeID)

	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Two loops: one accepting visitor streams, one keeping the control
	// stream warm and re-claiming when the served hostname set changes.
	errc := make(chan error, 2)
	go func() { errc <- a.acceptVisitorStreams(tunnelCtx, conn) }()
	go func() { errc <- a.maintainClaim(tunnelCtx, stream, claimed.Hostnames) }()

	select {
	case <-tunnelCtx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// maintainClaim keeps the control stream alive and re-claims when the set of
// served hostnames changes, which happens when the user adds their own domain.
func (a *Agent) maintainClaim(ctx context.Context, stream transport.Stream, claimed []string) error {
	ticker := time.NewTicker(transport.KeepAlivePeriod)
	defer ticker.Stop()

	have := strings.Join(claimed, ",")
	var seq uint64

	// The read side runs separately because the edge replies to pings and to
	// claims on the same stream, and both must be drained.
	replies := make(chan error, 1)
	go func() {
		for {
			if _, _, err := proto.ReadTyped(stream); err != nil {
				replies <- err
				return
			}
		}
	}()

	// reclaimIfChanged re-sends the claim when the hostname set has moved on.
	reclaimIfChanged := func() error {
		want := strings.Join(a.hostnameList(), ",")
		if want == have {
			return nil
		}
		if err := proto.WriteFrame(stream, proto.Claim{
			Type:      proto.TypeClaim,
			Hostnames: a.hostnameList(),
		}); err != nil {
			return err
		}
		have = want
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-replies:
			return err
		case <-a.reclaimSignal():
			// Someone added or removed a domain in the panel. Acting on it now
			// is the difference between a change that appears to work and one
			// that appears to have been ignored.
			if err := reclaimIfChanged(); err != nil {
				return err
			}
		case <-ticker.C:
			if err := reclaimIfChanged(); err != nil {
				return err
			}
			seq++
			if err := proto.WriteFrame(stream, proto.Ping{Type: proto.TypePing, Seq: seq}); err != nil {
				return err
			}
		}
	}
}

// reclaimSignal returns the channel that closes when the hostname set changes.
//
// The select in maintainClaim re-evaluates this on every pass, so a tunnel
// naturally picks up the replacement channel after each broadcast.
func (a *Agent) reclaimSignal() <-chan struct{} {
	a.reclaimMu.Lock()
	defer a.reclaimMu.Unlock()
	return a.reclaimCh
}

// notifyReclaim wakes every edge tunnel so they re-send their claim.
func (a *Agent) notifyReclaim() {
	a.reclaimMu.Lock()
	defer a.reclaimMu.Unlock()
	close(a.reclaimCh)
	a.reclaimCh = make(chan struct{})
}

// acceptVisitorStreams turns each incoming stream into a connection for the
// agent's own HTTP servers.
func (a *Agent) acceptVisitorStreams(ctx context.Context, conn transport.Conn) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go a.handleVisitorStream(ctx, conn, stream)
	}
}

// handleVisitorStream reads the one framed header on a data stream and hands
// the rest to the right server.
func (a *Agent) handleVisitorStream(ctx context.Context, conn transport.Conn, stream transport.Stream) {
	// The header must arrive promptly; after it, the stream lives as long as
	// the visitor's request does and must not carry a deadline.
	if err := stream.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		_ = stream.Close()
		return
	}
	var open proto.Open
	if err := proto.ReadExpect(stream, proto.TypeOpen, &open); err != nil {
		a.log.Debug("bad stream header", "error", err)
		_ = stream.Close()
		return
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		_ = stream.Close()
		return
	}

	// Serve only names this agent actually claims. An edge that forwards
	// something else — through a bug or through malice — gets nothing.
	if !a.serves(open.Host) {
		a.log.Warn("edge forwarded a hostname this agent does not serve", "host", open.Host)
		_ = stream.Close()
		return
	}

	remote := parseRemote(open.Remote)
	nc := conn.NetConnWithRemote(stream, remote)

	switch open.Proto {
	case proto.ProtoTLS:
		a.tlsStreams.deliver(ctx, nc)
	case proto.ProtoHTTP:
		a.httpStreams.deliver(ctx, nc)
	default:
		a.log.Debug("unknown stream protocol", "proto", open.Proto)
		_ = nc.Close()
	}
}

// serves reports whether this agent claims a hostname.
func (a *Agent) serves(host string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.hostnames[normalizeHost(host)]
}

// markEdgeUp and markEdgeDown maintain the status view's list of live edges.
func (a *Agent) markEdgeUp(edgeID string) {
	a.setStatus(func(s *Status) {
		for _, id := range s.ConnectedEdge {
			if id == edgeID {
				return
			}
		}
		s.ConnectedEdge = append(s.ConnectedEdge, edgeID)
	})
}

func (a *Agent) markEdgeDown(edgeID string) {
	a.setStatus(func(s *Status) {
		out := s.ConnectedEdge[:0]
		for _, id := range s.ConnectedEdge {
			if id != edgeID {
				out = append(out, id)
			}
		}
		s.ConnectedEdge = out
	})
}

// parseRemote turns the visitor address reported by the edge into a net.Addr.
//
// The value comes from the edge and is therefore not trusted for anything;
// it is used for logging only, and a malformed one is simply dropped.
func parseRemote(s string) net.Addr {
	if s == "" {
		return nil
	}
	addr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return nil
	}
	return addr
}

// streamListener presents tunnel streams to net/http as if they were ordinary
// accepted connections.
//
// This is what lets the agent run a completely standard Go HTTP and TLS stack
// over a transport it knows nothing about. The security value is that no part
// of TLS or HTTP has been reimplemented here.
type streamListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newStreamListener() *streamListener {
	return &streamListener{
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

// deliver hands a connection to the server, dropping it if the server has
// stopped or the visitor has waited too long for a worker.
func (l *streamListener) deliver(ctx context.Context, c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		_ = c.Close()
	case <-ctx.Done():
		_ = c.Close()
	case <-time.After(10 * time.Second):
		_ = c.Close()
	}
}

// Accept implements net.Listener.
func (l *streamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (l *streamListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr implements net.Listener. There is no real address: these connections
// arrive over a tunnel, and nothing is bound locally. Reporting that honestly
// is better than inventing a plausible-looking one.
func (l *streamListener) Addr() net.Addr { return tunnelAddr{} }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "meshmorphic" }
func (tunnelAddr) String() string  { return "tunnel" }

// normalizeHost lowercases a hostname and strips a trailing dot and any port.
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
