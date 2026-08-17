// Package gateway implements the MeshMorphic introduction service.
//
// A gateway is deliberately, aggressively ignorant. It keeps no database, no
// peer directory, no name register, and writes nothing to disk except the
// identity key it generated for itself on first run. It cannot issue a
// credential, because there is no credential in this protocol to issue. It
// never carries website traffic.
//
// What it does is answer one question — "who else is out there?" — and then
// get out of the way. An agent connects, proves which key it holds, is told
// which edges and which other gateways exist, and goes off to talk to them.
// The exchange is comparable to a ping.
//
// The consequences are the point:
//
//   - Taking over a gateway yields nothing. There is nothing stored to read,
//     no key that decrypts any traffic, and no authority to forge, because
//     hostnames are derived from each peer's own key rather than granted.
//   - Losing a gateway breaks nothing that is already running. Established
//     tunnels are agent-to-edge and do not pass through here.
//   - Gateways never need to agree with each other, so there is no cluster,
//     no replication and no split brain. Running fifty is exactly as simple
//     as running one, which is what makes volunteer redundancy realistic.
package gateway

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/proto"
	"github.com/lightmorphic/meshmorphic/internal/transport"
)

// Config configures a gateway.
type Config struct {
	// Listen is the UDP address for the QUIC introduction service.
	Listen string
	// Domains are the DNS suffixes whose wildcards point at this network's
	// edges, used to build the hostnames an agent is told it can serve. More
	// than one is supported so the network can add domains over time without
	// disturbing the peers already using an existing one.
	Domains []string
	// Identity is this gateway's keypair.
	Identity *identity.Identity
	// Seeds are other gateways known at start-up. They are gossiped onward to
	// agents. Nothing here is trusted: it is a list of doors, and a door that
	// holds nothing cannot mislead anyone by being the wrong door.
	Seeds []proto.GatewayInfo
	// Logger receives operational logs.
	Logger *slog.Logger
}

// Server is a running gateway.
type Server struct {
	cfg Config
	log *slog.Logger

	mu sync.RWMutex
	// edges holds the edges currently connected. Membership is liveness: an
	// edge that drops off is instantly no longer advertised, which is the
	// whole of the failover mechanism and needs no health checking.
	edges map[string]edgeEntry
	// agents holds live agent sessions so edge-list changes can be pushed.
	agents map[string]*session

	seen struct {
		peers int
	}
}

type edgeEntry struct {
	info proto.EdgeInfo
	// since is kept only for logging; it is not persisted anywhere.
	since time.Time
}

// session is one connected peer's control channel.
type session struct {
	peerID string
	send   chan any
	done   chan struct{}
}

// New creates a gateway server.
func New(cfg Config) (*Server, error) {
	if cfg.Identity == nil {
		return nil, errors.New("gateway: no identity")
	}
	if len(cfg.Domains) == 0 {
		return nil, errors.New("gateway: no domains configured")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	for i, d := range cfg.Domains {
		cfg.Domains[i] = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
	}
	return &Server{
		cfg:    cfg,
		log:    cfg.Logger,
		edges:  make(map[string]edgeEntry),
		agents: make(map[string]*session),
	}, nil
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := transport.Listen(s.cfg.Listen, s.cfg.Identity)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	s.log.Info("gateway listening",
		"addr", ln.Addr().String(),
		"gateway_id", s.cfg.Identity.ID(),
		"pubkey", identity.EncodeKey(s.cfg.Identity.PublicKey),
		"domains", strings.Join(s.cfg.Domains, ","))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A failed accept is usually one bad client, not a dead listener.
			s.log.Warn("accept failed", "error", err)
			continue
		}
		go s.serve(ctx, conn)
	}
}

// serve handles one connection for its lifetime.
func (s *Server) serve(ctx context.Context, conn transport.Conn) {
	defer func() { _ = conn.Close("closing") }()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	peer, err := transport.ServerHandshake(stream, s.cfg.Identity)
	if err != nil {
		s.log.Debug("handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}

	switch peer.Role {
	case proto.RoleEdge:
		s.serveEdge(ctx, conn, stream, peer)
	case proto.RoleAgent:
		s.serveAgent(ctx, conn, stream, peer)
	default:
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrProtocol, "unknown role %q", peer.Role))
	}
}

// serveEdge registers a connected edge for as long as it stays connected.
func (s *Server) serveEdge(ctx context.Context, conn transport.Conn, stream transport.Stream, peer *transport.PeerInfo) {
	// An edge must state the address agents should dial it on, since that is
	// its public address and not necessarily the source address seen here.
	var ann proto.Announce
	if err := proto.ReadExpect(stream, proto.TypeAnnounce, &ann); err != nil {
		s.log.Warn("edge did not announce", "edge", peer.PeerID, "error", err)
		return
	}
	if len(ann.Endpoints) == 0 {
		_ = proto.WriteFrame(stream, proto.Errorf(proto.ErrProtocol, "an edge must announce at least one endpoint"))
		return
	}

	info := proto.EdgeInfo{
		EdgeID: peer.PeerID,
		PubKey: identity.EncodeKey(peer.PubKey),
		Addr:   ann.Endpoints[0],
	}

	s.mu.Lock()
	s.edges[peer.PeerID] = edgeEntry{info: info, since: time.Now()}
	s.mu.Unlock()
	s.log.Info("edge available", "edge", peer.PeerID, "addr", info.Addr)

	if err := proto.WriteFrame(stream, proto.Welcome{
		Type:     proto.TypeWelcome,
		PeerID:   peer.PeerID,
		ServerID: s.cfg.Identity.ID(),
	}); err != nil {
		return
	}
	s.broadcastEdges()

	defer func() {
		s.mu.Lock()
		delete(s.edges, peer.PeerID)
		s.mu.Unlock()
		s.log.Info("edge gone", "edge", peer.PeerID)
		// Agents are told immediately so they can move to a surviving edge,
		// rather than discovering the loss when a visitor does.
		s.broadcastEdges()
	}()

	s.pump(ctx, conn, stream, nil)
}

// serveAgent introduces an agent to the network and then keeps the control
// channel open so it can be told when the edge list changes.
func (s *Server) serveAgent(ctx context.Context, conn transport.Conn, stream transport.Stream, peer *transport.PeerInfo) {
	// Everything the agent is told about itself is computed from the key it
	// just proved it holds. Nothing is looked up, because there is nowhere to
	// look, and nothing is assigned, because there is no authority here.
	label := identity.HostLabel(peer.PubKey)
	hostnames := make([]string, 0, len(s.cfg.Domains))
	for _, d := range s.cfg.Domains {
		hostnames = append(hostnames, label+"."+d)
	}

	sess := &session{
		peerID: peer.PeerID,
		send:   make(chan any, 8),
		done:   make(chan struct{}),
	}
	s.mu.Lock()
	// A reconnecting agent replaces its own earlier session; the old one is
	// closed so its writer goroutine does not linger.
	if old, ok := s.agents[peer.PeerID]; ok {
		close(old.done)
	}
	s.agents[peer.PeerID] = sess
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if cur, ok := s.agents[peer.PeerID]; ok && cur == sess {
			delete(s.agents, peer.PeerID)
		}
		s.mu.Unlock()
	}()

	welcome := proto.Welcome{
		Type:      proto.TypeWelcome,
		PeerID:    peer.PeerID,
		HostLabel: label,
		Hostnames: hostnames,
		Edges:     s.edgeList(),
		Gateways:  s.gatewayList(),
		ServerID:  s.cfg.Identity.ID(),
	}
	if err := proto.WriteFrame(stream, welcome); err != nil {
		return
	}
	s.log.Info("agent introduced",
		"peer", peer.PeerID, "hostnames", hostnames, "edges", len(welcome.Edges))

	s.pump(ctx, conn, stream, sess)
}

// pump runs the control loop: replies to pings, accepts announcements, and
// writes anything queued for this session.
//
// Reading and writing are split because pushes originate elsewhere; the read
// side owns the connection's lifetime and closing it stops the writer.
func (s *Server) pump(ctx context.Context, conn transport.Conn, stream transport.Stream, sess *session) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if sess != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-sess.done:
					_ = conn.Close("superseded by a newer session")
					return
				case msg := <-sess.send:
					if err := proto.WriteFrame(stream, msg); err != nil {
						cancel()
						return
					}
				}
			}
		}()
	}

	for {
		typ, body, err := proto.ReadTyped(stream)
		if err != nil {
			return
		}
		switch typ {
		case proto.TypePing:
			var p proto.Ping
			if err := proto.Decode(body, &p); err != nil {
				return
			}
			if err := proto.WriteFrame(stream, proto.Pong{Type: proto.TypePong, Seq: p.Seq}); err != nil {
				return
			}
		case proto.TypeAnnounce:
			// Accepted and discarded. Endpoint announcements matter for the
			// direct peer-to-peer paths of a later phase; recording them now
			// would mean storing something, which is the one thing a gateway
			// must not do.
		default:
			// Unknown types are ignored rather than fatal, so a newer agent
			// can talk to an older gateway without either side breaking.
			s.log.Debug("ignoring unknown message", "type", typ)
		}
	}
}

// edgeList snapshots the currently connected edges.
func (s *Server) edgeList() []proto.EdgeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]proto.EdgeInfo, 0, len(s.edges))
	for _, e := range s.edges {
		out = append(out, e.info)
	}
	return out
}

// gatewayList returns this gateway plus the peers it has been told about.
func (s *Server) gatewayList() []proto.GatewayInfo {
	out := make([]proto.GatewayInfo, 0, len(s.cfg.Seeds)+1)
	out = append(out, s.cfg.Seeds...)
	return out
}

// broadcastEdges tells every connected agent that the edge set changed.
func (s *Server) broadcastEdges() {
	msg := proto.Edges{Type: proto.TypeEdges, Edges: s.edgeList()}
	s.mu.RLock()
	sessions := make([]*session, 0, len(s.agents))
	for _, sess := range s.agents {
		sessions = append(sessions, sess)
	}
	s.mu.RUnlock()

	for _, sess := range sessions {
		// Never block: a wedged agent must not stall the announcement to
		// everybody else. A dropped update is recovered on its next reconnect.
		select {
		case sess.send <- msg:
		default:
			s.log.Debug("agent send queue full, skipping edge update", "peer", sess.peerID)
		}
	}
}

// Stats reports aggregate counts for monitoring.
//
// Deliberately aggregate: a gateway operator can see that their machine is
// working without being handed a list of who is using it. There is no
// endpoint anywhere that reveals peer identities, because that would make the
// gateway worth attacking.
type Stats struct {
	Edges  int `json:"edges"`
	Agents int `json:"agents"`
}

// Stats returns current counts.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Edges: len(s.edges), Agents: len(s.agents)}
}
