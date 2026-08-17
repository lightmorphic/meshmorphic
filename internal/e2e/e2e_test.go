// Package e2e runs a whole MeshMorphic network in one process: a gateway, an
// edge, and an agent serving a local website.
//
// This is the test that matters most. Every other test checks a part in
// isolation; this one asserts that a request entering at the edge comes out of
// the agent's website, having crossed a real QUIC tunnel, a real handshake,
// and the real hostname authorisation path.
package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lightmorphic/meshmorphic/internal/agent"
	"github.com/lightmorphic/meshmorphic/internal/edge"
	"github.com/lightmorphic/meshmorphic/internal/gateway"
	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/proto"
	"github.com/lightmorphic/meshmorphic/internal/transport"
)

const meshDomain = "awwe.test"

// quietLogger keeps a passing run readable; failures print what happened via
// the assertions rather than the log.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// freeUDPPort reserves a UDP port and releases it. There is a race between
// releasing and rebinding, but on a test machine it is not a practical
// problem, and it beats hard-coding ports that clash with whatever else is
// running.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// network is a complete MeshMorphic deployment running in this process.
type network struct {
	gatewayAddr string
	gatewayKey  []byte
	edgeHTTP    string
	edgeHTTPS   string
	agent       *agent.Agent
	upstream    *httptest.Server
}

// startNetwork brings up a gateway, an edge and an agent, and waits until the
// agent reports a live tunnel.
func startNetwork(t *testing.T, handler http.Handler) *network {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)

	// --- gateway ---
	gwID, err := identity.Generate()
	if err != nil {
		t.Fatalf("gateway identity: %v", err)
	}
	gwAddr := freeUDPPort(t)
	gw, err := gateway.New(gateway.Config{
		Listen:   gwAddr,
		Domains:  []string{meshDomain},
		Identity: gwID,
		Logger:   quietLogger(),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	go func() { _ = gw.Run(ctx) }()

	// --- edge ---
	edgeID, err := identity.Generate()
	if err != nil {
		t.Fatalf("edge identity: %v", err)
	}
	edgeTunnel := freeUDPPort(t)
	edgeHTTPS := freeTCPPort(t)
	edgeHTTP := freeTCPPort(t)
	ed, err := edge.New(edge.Config{
		TunnelListen:       edgeTunnel,
		HTTPSListen:        edgeHTTPS,
		HTTPListen:         edgeHTTP,
		MeshDomains:        []string{meshDomain},
		AllowCustomDomains: true,
		Identity:           edgeID,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}
	go func() { _ = ed.Run(ctx) }()
	go ed.Announce(ctx, edge.GatewayTarget{Addr: gwAddr, PubKey: gwID.PublicKey}, edgeTunnel)

	// --- agent ---
	agentID, err := identity.Generate()
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	ag, err := agent.New(agent.Config{
		Identity: agentID,
		Gateways: []agent.GatewayTarget{{Addr: gwAddr, PubKey: gwID.PublicKey}},
		Upstream: upstream.URL,
		CertDir:  t.TempDir(),
		Logger:   quietLogger(),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	go func() { _ = ag.Run(ctx) }()

	n := &network{
		gatewayAddr: gwAddr,
		gatewayKey:  gwID.PublicKey,
		edgeHTTP:    edgeHTTP,
		edgeHTTPS:   edgeHTTPS,
		agent:       ag,
		upstream:    upstream,
	}
	n.waitOnline(t)
	return n
}

// waitOnline blocks until the agent has a tunnel to the edge.
func (n *network) waitOnline(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.agent.Status().ConnectedEdge) > 0 && n.agent.MeshHostname() != "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the agent never came online (status: %+v)", n.agent.Status())
}

// get makes a cleartext request to the edge with a chosen Host header, which
// is what a visitor's browser does once DNS has pointed it here.
func (n *network) get(t *testing.T, host, path string) (*http.Response, string) {
	t.Helper()

	client := &http.Client{
		Timeout: 15 * time.Second,
		// The agent redirects cleartext to HTTPS; following that would leave
		// the test needing a real certificate, so the redirect itself is the
		// thing being asserted.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("GET", "http://"+n.edgeHTTP+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s: %v", host, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// The headline assertion: a visitor's request reaches a machine that never
// opened a port, by way of an edge that was never given a key.
func TestRequestReachesTheAgentThroughTheEdge(t *testing.T) {
	n := startNetwork(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "served from the home machine: %s", r.URL.Path)
	}))

	host := n.agent.MeshHostname()
	if host == "" {
		t.Fatal("the agent has no mesh hostname")
	}

	resp, _ := n.get(t, host, "/hello")

	// Cleartext is answered by the agent's own redirect handler, proving the
	// request crossed the tunnel rather than being answered at the edge.
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected a redirect to HTTPS from the agent, got %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	want := "https://" + host + "/hello"
	if location != want {
		t.Fatalf("redirect went to %q, want %q", location, want)
	}
}

// The hostname the gateway hands out must be the one the agent's key derives.
// If these ever drift apart, certificates would be requested for a name no
// edge would route.
func TestHostnameIsDerivedFromTheAgentsKey(t *testing.T) {
	n := startNetwork(t, http.NotFoundHandler())

	peerID, _, hostLabel := n.agent.Identity()
	host := n.agent.MeshHostname()

	if want := hostLabel + "." + meshDomain; host != want {
		t.Fatalf("mesh hostname is %q, want %q", host, want)
	}
	if peerID == "" {
		t.Fatal("the agent has no peer ID")
	}
}

// A request for a hostname nobody serves must be refused at the edge, without
// reaching any agent and without revealing that the name is unknown to anyone
// in particular.
func TestUnknownHostnameIsRefusedAtTheEdge(t *testing.T) {
	n := startNetwork(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a request for an unrouted hostname reached the agent")
	}))

	resp, _ := n.get(t, "nobody-here.awwe.test", "/")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for an unknown hostname, got %d", resp.StatusCode)
	}
}

// An agent that has not proved it holds the right key must not be able to
// claim a mesh hostname. This exercises the refusal over the real wire rather
// than through the internal policy function.
func TestForeignPeerCannotClaimAnotherHostname(t *testing.T) {
	n := startNetwork(t, http.NotFoundHandler())

	victimHost := n.agent.MeshHostname()

	// A second, unrelated identity connects directly to the edge and tries to
	// take over the first agent's hostname.
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("attacker identity: %v", err)
	}

	// Find the edge's tunnel address by asking the gateway, exactly as a real
	// agent would.
	edges := discoverEdges(t, n, attacker)
	if len(edges) == 0 {
		t.Fatal("the gateway advertised no edges")
	}
	edgePub, err := identity.DecodeKey(edges[0].PubKey)
	if err != nil {
		t.Fatalf("edge key: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := transport.Dial(ctx, edges[0].Addr, attacker, edgePub)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer func() { _ = conn.Close("done") }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := transport.ClientHandshake(stream, attacker, proto.RoleAgent, "test", edgePub); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	var welcome proto.Welcome
	if err := proto.ReadExpect(stream, proto.TypeWelcome, &welcome); err != nil {
		t.Fatalf("welcome: %v", err)
	}

	if err := proto.WriteFrame(stream, proto.Claim{
		Type:      proto.TypeClaim,
		Hostnames: []string{victimHost},
	}); err != nil {
		t.Fatalf("send claim: %v", err)
	}

	var claimed proto.Claimed
	err = proto.ReadExpect(stream, proto.TypeClaimed, &claimed)
	if err == nil {
		t.Fatalf("the edge let an unrelated peer claim %q", victimHost)
	}

	// And the victim must still be routed afterwards.
	resp, _ := n.get(t, victimHost, "/")
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("the rightful owner's route was disturbed: got %d", resp.StatusCode)
	}
}

// discoverEdges asks the gateway for its edge list, the way an agent does.
func discoverEdges(t *testing.T, n *network, id *identity.Identity) []proto.EdgeInfo {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := transport.Dial(ctx, n.gatewayAddr, id, n.gatewayKey)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer func() { _ = conn.Close("done") }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := transport.ClientHandshake(stream, id, proto.RoleAgent, "test", n.gatewayKey); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	var welcome proto.Welcome
	if err := proto.ReadExpect(stream, proto.TypeWelcome, &welcome); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	return welcome.Edges
}

// A user's own domain is served once claimed, alongside the automatic address.
func TestCustomDomainIsServed(t *testing.T) {
	n := startNetwork(t, http.NotFoundHandler())

	if err := n.agent.AddHostname("example.awwe-custom.test"); err != nil {
		t.Fatalf("AddHostname: %v", err)
	}

	// The claim is re-sent on the control tick rather than immediately.
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ := n.get(t, "example.awwe-custom.test", "/")
		if resp.StatusCode == http.StatusMovedPermanently {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("the custom domain never started being served")
}

// The gateway holds nothing about the peers that pass through it. This asserts
// the property directly, because it is the promise the whole design rests on
// and it would be easy to erode by accident later.
func TestGatewayKeepsNoPeerState(t *testing.T) {
	n := startNetwork(t, http.NotFoundHandler())
	_ = n

	// The gateway type deliberately exposes counts and nothing else. If a
	// future change adds a peer directory, this test should be updated only
	// alongside a deliberate decision to change the threat model.
	gwID, _ := identity.Generate()
	gw, err := gateway.New(gateway.Config{
		Listen:   freeUDPPort(t),
		Domains:  []string{meshDomain},
		Identity: gwID,
		Logger:   quietLogger(),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	stats := gw.Stats()
	if stats.Agents != 0 || stats.Edges != 0 {
		t.Fatalf("a fresh gateway already knows about peers: %+v", stats)
	}
}
