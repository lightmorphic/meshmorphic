package edge

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
	"github.com/FOSSCharlie/meshmorphic/internal/transport"
)

func testEdge(t *testing.T, allowCustom bool) *Server {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv, err := New(Config{
		TunnelListen:       "127.0.0.1:0",
		HTTPSListen:        "127.0.0.1:0",
		HTTPListen:         "127.0.0.1:0",
		MeshDomains:        []string{"awwe.uk", "mm.example.net"},
		AllowCustomDomains: allowCustom,
		Identity:           id,
		Logger:             slog.New(slog.NewTextHandler(discard{}, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func testTunnel(t *testing.T) (*tunnel, *identity.Identity) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return &tunnel{peerID: id.ID(), pubKey: id.PublicKey, conn: transport.Conn{}}, id
}

// This is the check that replaces a name register. A peer may serve exactly
// the mesh hostname its key derives, and no other. If this ever passes for a
// label the key does not produce, any peer could take any other peer's site.
func TestAuthorizeMeshHostnameRequiresMatchingKey(t *testing.T) {
	srv := testEdge(t, false)
	tun, id := testTunnel(t)

	own := identity.HostLabel(id.PublicKey) + ".awwe.uk"
	if err := srv.authorize(tun, own); err != nil {
		t.Fatalf("a peer was refused its own derived hostname: %v", err)
	}

	// The same key must be entitled to its label under every mesh domain.
	if err := srv.authorize(tun, identity.HostLabel(id.PublicKey)+".mm.example.net"); err != nil {
		t.Fatalf("a peer was refused its label under a second mesh domain: %v", err)
	}

	// Somebody else's label must be refused.
	other, _ := identity.Generate()
	stolen := identity.HostLabel(other.PublicKey) + ".awwe.uk"
	if err := srv.authorize(tun, stolen); err == nil {
		t.Fatal("a peer was allowed to claim another peer's mesh hostname")
	}
}

func TestAuthorizeRejectsMalformedMeshLabels(t *testing.T) {
	srv := testEdge(t, false)
	tun, id := testTunnel(t)
	label := identity.HostLabel(id.PublicKey)

	for _, host := range []string{
		"anything.awwe.uk",
		strings.ToUpper(label) + "x.awwe.uk",
		label + "x.awwe.uk",
		"sub." + label + ".awwe.uk", // extra label: not a single-label mesh name
		label[:len(label)-1] + ".awwe.uk",
	} {
		if err := srv.authorize(tun, host); err == nil {
			t.Fatalf("edge accepted the invalid mesh hostname %q", host)
		}
	}
}

// With custom domains switched off, an edge serves the mesh and nothing else.
func TestAuthorizeCustomDomainsDisabled(t *testing.T) {
	srv := testEdge(t, false)
	tun, _ := testTunnel(t)

	if err := srv.authorize(tun, "example.com"); err == nil {
		t.Fatal("an edge with custom domains disabled accepted one")
	}
}

// With custom domains on, the first claimant wins and a second peer cannot
// take the name from under them.
func TestAuthorizeCustomDomainsFirstComeFirstServed(t *testing.T) {
	srv := testEdge(t, true)
	first, _ := testTunnel(t)
	second, _ := testTunnel(t)

	accepted, rejected := srv.claim(first, []string{"example.com"})
	if len(accepted) != 1 || len(rejected) != 0 {
		t.Fatalf("first claim failed: accepted=%v rejected=%v", accepted, rejected)
	}
	if err := srv.authorize(second, "example.com"); err == nil {
		t.Fatal("a second peer was allowed to take a custom domain already in use")
	}
	// The original holder must be able to re-claim, which happens on every
	// reconnect and whenever its hostname set changes.
	if err := srv.authorize(first, "example.com"); err != nil {
		t.Fatalf("the holder was refused its own domain on re-claim: %v", err)
	}
}

// A departing tunnel must withdraw only its own routes. Getting this wrong
// would mean a reconnecting peer knocks out the very route it just installed.
func TestWithdrawOnlyRemovesOwnRoutes(t *testing.T) {
	srv := testEdge(t, true)
	old, id := testTunnel(t)

	host := identity.HostLabel(id.PublicKey) + ".awwe.uk"
	if accepted, _ := srv.claim(old, []string{host}); len(accepted) != 1 {
		t.Fatal("initial claim failed")
	}

	// The same peer reconnects: a new tunnel object, same identity.
	fresh := &tunnel{peerID: id.ID(), pubKey: id.PublicKey}
	if accepted, _ := srv.claim(fresh, []string{host}); len(accepted) != 1 {
		t.Fatal("re-claim failed")
	}

	// Now the old tunnel finishes tearing down.
	srv.withdrawAll(old)

	if _, ok := srv.lookup(host); !ok {
		t.Fatal("the old tunnel's teardown removed the new tunnel's route")
	}
}

func TestClaimNormalizesHostnames(t *testing.T) {
	srv := testEdge(t, true)
	tun, _ := testTunnel(t)

	accepted, rejected := srv.claim(tun, []string{"Example.COM.", "  spaced.example.com  "})
	if len(rejected) != 0 {
		t.Fatalf("unexpected rejections: %v", rejected)
	}
	for _, want := range []string{"example.com", "spaced.example.com"} {
		if _, ok := srv.lookup(want); !ok {
			t.Fatalf("hostname %q was not normalised into the routing table (accepted: %v)", want, accepted)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":      "example.com",
		"example.com.":     "example.com",
		"example.com:443":  "example.com",
		"  example.com  ":  "example.com",
		"[::1]:443":        "[::1]",
		"example.com.:443": "example.com",
		"EXAMPLE.COM:8443": "example.com",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// discard swallows log output during tests.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
