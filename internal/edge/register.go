package edge

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/FOSSCharlie/meshmorphic/internal/proto"
	"github.com/FOSSCharlie/meshmorphic/internal/transport"
	"github.com/FOSSCharlie/meshmorphic/internal/version"
)

// GatewayTarget is a gateway this edge announces itself to.
type GatewayTarget struct {
	Addr   string
	PubKey ed25519.PublicKey
}

// Announce keeps this edge registered with a gateway for as long as ctx lives.
//
// The edge dials outward, exactly as an agent does. Presence is the
// registration: while this connection is up the gateway advertises the edge,
// and the moment it drops the gateway stops. There is no health check to
// configure, no timeout to tune, and nothing written down that could go stale.
//
// Because a gateway holds no state, there is nothing to reconcile after an
// outage either — the edge simply reconnects and is advertised again.
func (s *Server) Announce(ctx context.Context, target GatewayTarget, publicAddr string) {
	backoff := time.Second
	const maxBackoff = time.Minute

	for ctx.Err() == nil {
		err := s.announceOnce(ctx, target, publicAddr)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.log.Warn("gateway announcement ended", "gateway", target.Addr, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		// Exponential backoff with a ceiling: a gateway that is down should
		// not be hammered, but should be picked up promptly when it returns.
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// announceOnce holds one registration session until it fails.
func (s *Server) announceOnce(ctx context.Context, target GatewayTarget, publicAddr string) error {
	conn, err := transport.Dial(ctx, target.Addr, s.cfg.Identity, target.PubKey)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close("closing") }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	if err := transport.ClientHandshake(stream, s.cfg.Identity, proto.RoleEdge, version.Version, target.PubKey); err != nil {
		return fmt.Errorf("edge: handshake with gateway %s: %w", target.Addr, err)
	}
	// The gateway cannot infer the address agents should dial: the source
	// address it observes may be behind NAT or a different interface. The edge
	// states it, because the edge is the only one that knows.
	if err := proto.WriteFrame(stream, proto.Announce{
		Type:      proto.TypeAnnounce,
		Endpoints: []string{publicAddr},
	}); err != nil {
		return err
	}
	var welcome proto.Welcome
	if err := proto.ReadExpect(stream, proto.TypeWelcome, &welcome); err != nil {
		return err
	}
	s.log.Info("announced to gateway", "gateway", target.Addr, "gateway_id", welcome.ServerID, "as", publicAddr)

	// Keepalives double as liveness: when they stop being answered the
	// gateway drops this edge from its list within one idle timeout.
	ticker := time.NewTicker(transport.KeepAlivePeriod)
	defer ticker.Stop()
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-conn.Context().Done():
			return fmt.Errorf("edge: gateway %s closed the connection", target.Addr)
		case <-ticker.C:
			seq++
			if err := proto.WriteFrame(stream, proto.Ping{Type: proto.TypePing, Seq: seq}); err != nil {
				return err
			}
			var pong proto.Pong
			if err := proto.ReadExpect(stream, proto.TypePong, &pong); err != nil {
				return err
			}
		}
	}
}
