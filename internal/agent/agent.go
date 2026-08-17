// Package agent implements the MeshMorphic home-server component.
//
// The agent is the only part of this system that runs on a machine belonging
// to someone who is nervous about the internet, and every design choice here
// follows from that.
//
// It never listens on a public port. It dials outward — to a gateway to ask
// who is out there, then to an edge to establish one tunnel — and every
// visitor to the website arrives as a new stream on that existing outbound
// connection. From the internet's point of view the home machine has no open
// door to knock on, because it has not opened one.
//
// TLS terminates here, on the home machine. The certificate's private key is
// generated here and never leaves. The edge in the middle carries ciphertext
// it cannot read, which is what makes it safe to let a stranger run one.
package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/names"
	"github.com/lightmorphic/meshmorphic/internal/proto"
	"github.com/lightmorphic/meshmorphic/internal/transport"
	"github.com/lightmorphic/meshmorphic/internal/version"
)

// GatewayTarget is a gateway the agent can bootstrap from.
type GatewayTarget struct {
	Addr   string
	PubKey ed25519.PublicKey
}

// Config configures an agent.
type Config struct {
	// Identity is this agent's keypair, generated on first run.
	Identity *identity.Identity
	// Gateways are the introduction points to try. Any one is sufficient; they
	// are tried in order and the list is extended by gossip as the agent
	// learns of others.
	Gateways []GatewayTarget
	// Upstream is the local website to serve, e.g. http://127.0.0.1:8080.
	// In the packaged setup this is the sandboxed site container, reachable
	// only on an internal network with no route to anywhere else.
	Upstream string
	// CertDir is where Let's Encrypt certificates and their private keys are
	// cached. These never leave the machine.
	CertDir string
	// CustomHostnames are additional names the user owns and has pointed at
	// the network's edges.
	CustomHostnames []string
	// ACMEEmail is optional and passed to Let's Encrypt for expiry warnings.
	ACMEEmail string
	// ACMEStaging uses Let's Encrypt's staging environment, which issues
	// untrusted certificates but has generous rate limits. Essential while
	// testing, because the production limits are unforgiving.
	ACMEStaging bool
	// Logger receives operational logs.
	Logger *slog.Logger
}

// Agent is a running home-server agent.
type Agent struct {
	cfg      Config
	log      *slog.Logger
	upstream *url.URL

	certs *autocert.Manager

	// tlsStreams and httpStreams turn incoming tunnel streams into something
	// net/http can accept, so the ordinary Go HTTP server runs unmodified over
	// a transport it knows nothing about.
	tlsStreams  *streamListener
	httpStreams *streamListener

	mu        sync.RWMutex
	hostnames map[string]bool
	edges     []proto.EdgeInfo
	// active tracks the edge tunnels currently being maintained.
	active map[string]context.CancelFunc
	// reclaimCh wakes every edge tunnel when the served hostname set changes,
	// so adding a domain in the panel takes effect immediately rather than on
	// the next keepalive.
	//
	// Broadcast by closing: every tunnel waits on the same channel, and
	// closing it releases all of them at once. A buffered channel would wake
	// only one, which with several edges would leave the rest unaware.
	reclaimMu sync.Mutex
	reclaimCh chan struct{}

	statusMu sync.RWMutex
	status   Status
}

// Status is the human-facing state of the agent, surfaced by the CLI so a
// non-technical user can see whether their website is working without reading
// a log file.
type Status struct {
	PeerID        string    `json:"peer_id"`
	Nickname      string    `json:"nickname"`
	Hostnames     []string  `json:"hostnames"`
	GatewayID     string    `json:"gateway_id"`
	ConnectedEdge []string  `json:"connected_edges"`
	Since         time.Time `json:"since"`
	LastError     string    `json:"last_error,omitempty"`
}

// New creates an agent.
func New(cfg Config) (*Agent, error) {
	if cfg.Identity == nil {
		return nil, errors.New("agent: no identity")
	}
	if len(cfg.Gateways) == 0 {
		return nil, errors.New("agent: no gateways configured")
	}
	if cfg.Upstream == "" {
		return nil, errors.New("agent: no upstream website configured")
	}
	if cfg.CertDir == "" {
		return nil, errors.New("agent: no certificate directory configured")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("agent: parse upstream %q: %w", cfg.Upstream, err)
	}

	a := &Agent{
		cfg:         cfg,
		log:         cfg.Logger,
		upstream:    up,
		tlsStreams:  newStreamListener(),
		httpStreams: newStreamListener(),
		hostnames:   make(map[string]bool),
		active:      make(map[string]context.CancelFunc),
		reclaimCh:   make(chan struct{}),
	}
	for _, h := range cfg.CustomHostnames {
		a.hostnames[normalizeHost(h)] = true
	}

	a.certs = &autocert.Manager{
		Cache: autocert.DirCache(cfg.CertDir),
		// The certificate is only ever requested for a name the agent is
		// actually serving, so this policy is the whole of the guard against
		// being used to mint certificates for anything else.
		HostPolicy: a.hostAllowed,
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.ACMEEmail,
	}
	if cfg.ACMEStaging {
		a.certs.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	a.setStatus(func(s *Status) {
		s.PeerID = cfg.Identity.ID()
		s.Nickname = names.Nickname(cfg.Identity.PublicKey)
	})
	return a, nil
}

// hostAllowed is autocert's policy hook: certificates are requested only for
// names this agent is currently serving.
func (a *Agent) hostAllowed(_ context.Context, host string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.hostnames[normalizeHost(host)] {
		return nil
	}
	return fmt.Errorf("agent: not serving %q", host)
}

// Run starts the agent and serves until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	proxy := a.newProxy()

	// The visitor-facing HTTPS server. It runs over streams arriving from an
	// edge, with TLS terminating here rather than anywhere public.
	httpsSrv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          nil,
	}
	tlsConf := a.certs.TLSConfig()
	tlsConf.MinVersion = tls.VersionTLS12

	// The cleartext server. It answers ACME challenges and otherwise sends
	// people to the secure address; it never serves site content.
	httpSrv := &http.Server{
		Handler:           a.certs.HTTPHandler(http.HandlerFunc(redirectToHTTPS)),
		ReadHeaderTimeout: 20 * time.Second,
	}

	go func() {
		if err := httpsSrv.Serve(tls.NewListener(a.tlsStreams, tlsConf)); err != nil && ctx.Err() == nil {
			a.log.Error("https server stopped", "error", err)
		}
	}()
	go func() {
		if err := httpSrv.Serve(a.httpStreams); err != nil && ctx.Err() == nil {
			a.log.Error("http server stopped", "error", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpsSrv.Shutdown(shutdownCtx)
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	a.log.Info("agent starting",
		"peer_id", a.cfg.Identity.ID(),
		"nickname", names.Nickname(a.cfg.Identity.PublicKey),
		"upstream", a.cfg.Upstream)

	return a.superviseGateway(ctx)
}

// superviseGateway keeps a gateway session alive, moving to another gateway
// when one fails.
//
// Failing over is cheap and safe precisely because a gateway holds nothing:
// there is no session to migrate and no state to reconcile. Any gateway will
// give the same answer, so trying the next one is a complete recovery.
func (a *Agent) superviseGateway(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 2 * time.Minute
	attempt := 0

	for ctx.Err() == nil {
		targets := a.gatewayTargets()
		target := targets[attempt%len(targets)]
		attempt++

		err := a.runGatewaySession(ctx, target)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Warn("gateway session ended", "gateway", target.Addr, "error", err)
			a.setStatus(func(s *Status) { s.LastError = err.Error() })
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return nil
}

// gatewayTargets snapshots the gateways currently worth trying.
func (a *Agent) gatewayTargets() []GatewayTarget {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]GatewayTarget, len(a.cfg.Gateways))
	copy(out, a.cfg.Gateways)
	return out
}

// runGatewaySession holds one gateway connection, reconciling edge tunnels as
// the gateway reports changes.
func (a *Agent) runGatewaySession(ctx context.Context, target GatewayTarget) error {
	conn, err := transport.Dial(ctx, target.Addr, a.cfg.Identity, target.PubKey)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close("closing") }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	if err := transport.ClientHandshake(stream, a.cfg.Identity, proto.RoleAgent, version.Version, target.PubKey); err != nil {
		return fmt.Errorf("agent: handshake with gateway %s: %w", target.Addr, err)
	}

	var welcome proto.Welcome
	if err := proto.ReadExpect(stream, proto.TypeWelcome, &welcome); err != nil {
		return err
	}

	// The gateway does not grant the hostname, it computes it. Recomputing it
	// locally means a hostile gateway cannot talk this agent into serving, or
	// requesting a certificate for, a name that is not its own.
	expected := identity.HostLabel(a.cfg.Identity.PublicKey)
	for _, h := range welcome.Hostnames {
		label, _, ok := cutLabel(h)
		if !ok || label != expected {
			return fmt.Errorf("agent: gateway %s offered hostname %q, which this key does not derive; refusing", target.Addr, h)
		}
	}
	a.addHostnames(welcome.Hostnames)
	a.learnGateways(welcome.Gateways)

	a.setStatus(func(s *Status) {
		s.GatewayID = welcome.ServerID
		s.Since = time.Now()
		s.LastError = ""
		s.Hostnames = a.hostnameList()
	})
	a.log.Info("introduced to the mesh",
		"gateway", target.Addr,
		"hostnames", a.hostnameList(),
		"edges", len(welcome.Edges))

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer a.stopAllEdges()

	a.reconcileEdges(sessionCtx, welcome.Edges)

	// Keepalives run on their own goroutine so the read loop can stay blocked
	// on the gateway's pushes.
	go a.keepalive(sessionCtx, stream)

	for {
		typ, body, err := proto.ReadTyped(stream)
		if err != nil {
			return err
		}
		switch typ {
		case proto.TypeEdges:
			var e proto.Edges
			if err := proto.Decode(body, &e); err != nil {
				return err
			}
			a.log.Info("edge list changed", "edges", len(e.Edges))
			a.reconcileEdges(sessionCtx, e.Edges)
		case proto.TypeGateways:
			var g proto.Gateways
			if err := proto.Decode(body, &g); err != nil {
				return err
			}
			a.learnGateways(g.Gateways)
		case proto.TypePong:
			// Expected; nothing to do.
		default:
			a.log.Debug("ignoring unknown message", "type", typ)
		}
	}
}

// keepalive sends periodic pings so a dead gateway is noticed promptly.
func (a *Agent) keepalive(ctx context.Context, stream transport.Stream) {
	ticker := time.NewTicker(transport.KeepAlivePeriod)
	defer ticker.Stop()
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seq++
			if err := proto.WriteFrame(stream, proto.Ping{Type: proto.TypePing, Seq: seq}); err != nil {
				return
			}
		}
	}
}

// learnGateways folds gossiped gateways into the list of places to try.
//
// This gossip is unauthenticated, and that is sound rather than sloppy: a
// gateway can neither read traffic nor authorise anything, so the worst a
// fabricated entry achieves is one wasted dial before the agent moves on.
// Entries are added, never removed, so a hostile gateway cannot shrink the
// agent's options down to one it controls.
func (a *Agent) learnGateways(list []proto.GatewayInfo) {
	if len(list) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	known := make(map[string]bool, len(a.cfg.Gateways))
	for _, g := range a.cfg.Gateways {
		known[g.Addr] = true
	}
	for _, g := range list {
		if g.Addr == "" || known[g.Addr] {
			continue
		}
		pub, err := identity.DecodeKey(g.PubKey)
		if err != nil {
			continue
		}
		a.cfg.Gateways = append(a.cfg.Gateways, GatewayTarget{Addr: g.Addr, PubKey: pub})
		known[g.Addr] = true
		a.log.Info("learned a new gateway", "addr", g.Addr, "gateway_id", g.GatewayID)
	}
}

// reconcileEdges starts tunnels to edges that are new and stops tunnels to
// edges that have gone.
func (a *Agent) reconcileEdges(ctx context.Context, list []proto.EdgeInfo) {
	wanted := make(map[string]proto.EdgeInfo, len(list))
	for _, e := range list {
		wanted[e.EdgeID] = e
	}

	a.mu.Lock()
	a.edges = list
	for id, cancel := range a.active {
		if _, keep := wanted[id]; !keep {
			cancel()
			delete(a.active, id)
		}
	}
	// Each tunnel gets its own context so that a single edge disappearing from
	// the list stops only that tunnel.
	type pending struct {
		info proto.EdgeInfo
		ctx  context.Context
	}
	var start []pending
	for id, e := range wanted {
		if _, running := a.active[id]; running {
			continue
		}
		edgeCtx, cancel := context.WithCancel(ctx)
		a.active[id] = cancel
		start = append(start, pending{info: e, ctx: edgeCtx})
	}
	a.mu.Unlock()

	// Tunnels are started outside the lock so a slow dial cannot hold up the
	// control loop.
	for _, p := range start {
		go a.superviseEdge(p.ctx, p.info)
	}
}

// stopAllEdges tears down every edge tunnel, used when the gateway session ends.
func (a *Agent) stopAllEdges() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, cancel := range a.active {
		cancel()
		delete(a.active, id)
	}
}

// setStatus mutates the status snapshot under its own lock.
func (a *Agent) setStatus(f func(*Status)) {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	f(&a.status)
}

// Status returns a snapshot of the agent's state.
func (a *Agent) Status() Status {
	a.statusMu.RLock()
	defer a.statusMu.RUnlock()
	s := a.status
	s.Hostnames = append([]string(nil), s.Hostnames...)
	s.ConnectedEdge = append([]string(nil), s.ConnectedEdge...)
	return s
}

// addHostnames records names this agent should serve and request certificates
// for.
func (a *Agent) addHostnames(list []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, h := range list {
		if h = normalizeHost(h); h != "" {
			a.hostnames[h] = true
		}
	}
}

// hostnameList snapshots the served hostnames in a stable order.
func (a *Agent) hostnameList() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.hostnames))
	for h := range a.hostnames {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// newProxy builds the reverse proxy to the local website.
func (a *Agent) newProxy() http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(a.upstream)
	proxy.Transport = &http.Transport{
		// The upstream is a container on an internal network one hop away.
		// Short timeouts here surface a broken site quickly rather than
		// leaving a visitor watching a spinner.
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}
	original := proxy.Director
	proxy.Director = func(r *http.Request) {
		original(r)
		// Preserve the name the visitor asked for, so the site can generate
		// correct absolute links, and tell it the session was secure even
		// though this last hop is not.
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		a.log.Warn("upstream website unreachable", "error", err, "path", r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(upstreamDownPage))
	}
	return proxy
}

// redirectToHTTPS sends cleartext visitors to the secure address.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + normalizeHost(r.Host) + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// upstreamDownPage is shown when the site container is not answering. It says
// what happened in words the site's owner can act on, and does not leak
// anything about the machine to a passing visitor.
const upstreamDownPage = `<!doctype html>
<meta charset="utf-8">
<title>Site unavailable</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 20vh auto; padding: 0 1.5rem; line-height: 1.6; }
  h1 { font-size: 1.25rem; }
  p { color: #444; }
</style>
<h1>This site is not responding right now</h1>
<p>The connection to the internet is working, but the website itself did not
answer. If this is your site, check that its container is running.</p>
`

// cutLabel splits a hostname into its first label and the rest.
func cutLabel(host string) (label, rest string, ok bool) {
	host = normalizeHost(host)
	for i := range len(host) {
		if host[i] == '.' {
			return host[:i], host[i+1:], i > 0
		}
	}
	return "", "", false
}
