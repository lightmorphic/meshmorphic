// Package panel serves the MeshMorphic settings interface on the local
// network.
//
// The panel is the only interface most users will ever see, and its job is to
// make a genuinely unusual security posture feel ordinary. It shows what is
// happening in plain words, lets someone put a website on the machine, add a
// domain they own, and write down the one thing that cannot be recovered.
//
// It is never reachable from the internet. It binds to the local network,
// refuses requests whose Host header is not a local address, and requires a
// device to be paired before it will do anything. See devices.go for why
// "local network" alone was not considered a sufficient boundary.
package panel

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/recovery"
	"github.com/lightmorphic/meshmorphic/internal/version"
)

//go:embed assets templates
var assetsFS embed.FS

// Controller is the slice of the agent the panel is allowed to touch.
//
// Defining it here rather than importing the agent's concrete type keeps the
// panel unable to reach anything not listed, and makes the boundary visible
// in one place.
type Controller interface {
	Status() Status
	Identity() (peerID, nickname, hostLabel string)
	MeshHostname() string
	CustomHostnames() []string
	AddHostname(host string) error
	RemoveHostname(host string) error
}

// Status is the agent state the panel renders.
type Status struct {
	PeerID         string
	Nickname       string
	Hostnames      []string
	GatewayID      string
	ConnectedEdges []string
	Since          time.Time
	LastError      string
}

// Config configures the panel.
type Config struct {
	// Listen is the local address to bind, e.g. 0.0.0.0:8800. Binding the
	// local network rather than only loopback is deliberate: people set this
	// up on a headless box and configure it from a laptop.
	Listen string
	// StateDir holds the device list.
	StateDir string
	// SiteDir is where the website's files live. The site container serves
	// this directory read-only.
	SiteDir string
	// Identity is needed to render the recovery key.
	Identity *identity.Identity
	// Control is the agent.
	Control Controller
	// Logger receives operational logs.
	Logger *slog.Logger
}

// Server is the running panel.
type Server struct {
	cfg     Config
	log     *slog.Logger
	devices *deviceStore
	tpl     *template.Template
}

// New creates a panel server.
func New(cfg Config) (*Server, error) {
	if cfg.Control == nil {
		return nil, errors.New("panel: no controller")
	}
	if cfg.Identity == nil {
		return nil, errors.New("panel: no identity")
	}
	if cfg.SiteDir == "" {
		return nil, errors.New("panel: no site directory")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	devices, err := openDeviceStore(cfg.StateDir + "/panel-devices.json")
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("").Funcs(templateFuncs()).ParseFS(assetsFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("panel: parse templates: %w", err)
	}
	return &Server{cfg: cfg, log: cfg.Logger, devices: devices, tpl: tpl}, nil
}

// Handler builds the panel's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, err := newStaticHandler()
	if err != nil {
		// Assets are embedded at build time; a failure here means a broken
		// binary, not a runtime condition worth degrading gracefully for.
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", static))

	// Pairing routes sit outside the device requirement, because a device that
	// is not yet paired has to be able to ask.
	mux.HandleFunc("GET /pair", s.handlePair)
	mux.HandleFunc("GET /pair/status", s.handlePairStatus)

	mux.Handle("GET /{$}", s.requireDevice(http.HandlerFunc(s.handleHome)))
	mux.Handle("GET /site", s.requireDevice(http.HandlerFunc(s.handleSite)))
	mux.Handle("POST /site/upload", s.requireDevice(http.HandlerFunc(s.handleUpload)))
	mux.Handle("GET /domains", s.requireDevice(http.HandlerFunc(s.handleDomains)))
	mux.Handle("POST /domains/add", s.requireDevice(http.HandlerFunc(s.handleDomainAdd)))
	mux.Handle("POST /domains/remove", s.requireDevice(http.HandlerFunc(s.handleDomainRemove)))
	mux.Handle("GET /recovery", s.requireDevice(http.HandlerFunc(s.handleRecovery)))
	mux.Handle("GET /devices", s.requireDevice(http.HandlerFunc(s.handleDevices)))
	mux.Handle("POST /devices/approve", s.requireDevice(http.HandlerFunc(s.handleDeviceApprove)))
	mux.Handle("POST /devices/revoke", s.requireDevice(http.HandlerFunc(s.handleDeviceRevoke)))

	return s.securityHeaders(s.requireLocalHost(mux))
}

// Run serves the panel until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Uploads of a website can be large and a home upload is slow, so the
		// write timeout is generous. The read timeout is not set at all for
		// the same reason; ReadHeaderTimeout covers the slowloris case.
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.log.Info("settings panel listening", "addr", s.cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("panel: serve: %w", err)
	}
	return nil
}

// securityHeaders applies a strict policy to every response.
//
// The content security policy allows nothing external at all, which is easy to
// promise because the panel loads nothing external: no CDN, no font service,
// no analytics. A panel that phoned home would undercut the entire product.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; "+
				"script-src 'self'; font-src 'self'; connect-src 'self'; "+
				"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requireLocalHost rejects requests whose Host header is not a local address,
// and rejects cross-origin writes.
//
// This is the defence against DNS rebinding, which is the one way a page on
// the public internet could otherwise reach a service bound to a private
// address. An attacker's site resolves its own name to the victim's internal
// IP and then makes requests to it from the victim's browser; the browser
// considers those same-origin. Pinning the acceptable Host values breaks it,
// because the attacker's domain is never in the list.
func (s *Server) requireLocalHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalHostHeader(r.Host) {
			http.Error(w, "The settings panel only answers to local addresses.", http.StatusMisdirectedRequest)
			return
		}
		// Any request that changes something must demonstrably come from the
		// panel's own pages, not from another site the browser has open.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := checkSameOrigin(r); err != nil {
				s.log.Warn("rejected a cross-origin write", "path", r.URL.Path, "error", err)
				http.Error(w, "This request did not come from the settings panel.", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalHostHeader reports whether a Host header names this machine on a
// local network.
func isLocalHostHeader(host string) bool {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return true
	}
	// Names published by multicast DNS, which is how a headless box is found
	// on a home network.
	if name == "meshmorphic.local" || strings.HasSuffix(name, ".local") {
		return true
	}
	ip := net.ParseIP(strings.Trim(name, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// checkSameOrigin verifies a state-changing request originated from the panel.
//
// Two independent signals are used. Sec-Fetch-Site is sent by current browsers
// and cannot be forged by page script. Origin is the older check and covers
// anything that does not send the newer header. Requiring one of them to be
// present and correct means a silent absence of both is refused rather than
// waved through.
func checkSameOrigin(r *http.Request) error {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return nil
	case "":
		// Fall through to the Origin check for older clients.
	default:
		return fmt.Errorf("Sec-Fetch-Site was %q", r.Header.Get("Sec-Fetch-Site"))
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return errors.New("no Origin and no Sec-Fetch-Site header")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("unparseable Origin %q", origin)
	}
	// Scheme is compared as well as host. An origin differing only by scheme
	// is a different origin to the browser, and accepting it would widen the
	// check for no benefit — the panel is only ever served one way.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if !strings.EqualFold(u.Scheme, scheme) || !strings.EqualFold(u.Host, r.Host) {
		return fmt.Errorf("Origin %q does not match %s://%s", origin, scheme, r.Host)
	}
	return nil
}

// requireDevice enforces device pairing.
func (s *Server) requireDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := deviceToken(r)
		if s.devices.Verify(token) {
			next.ServeHTTP(w, r)
			return
		}
		// First run: the machine has just been set up and whoever is looking
		// at it is the person who set it up. Enrolling them silently is the
		// difference between a product that works and one that opens with a
		// security dialogue nobody understands.
		if s.devices.Empty() {
			newTok, err := s.devices.Enroll(describeDevice(r))
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			setDeviceCookie(w, newTok)
			s.log.Info("first device enrolled", "device", describeDevice(r))
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/pair", http.StatusSeeOther)
	})
}

// handlePair shows the approval code for a device that is not yet paired.
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	if s.devices.Verify(deviceToken(r)) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	req, err := s.devices.RequestAccess(describeDevice(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// The waiting device holds its future token from the outset; it only
	// becomes usable once somebody approves the matching code.
	setDeviceCookie(w, req.Token)
	s.render(w, r, "pair.html", map[string]any{
		"Title": "Approve this device",
		"Code":  req.Code,
	})
}

// handlePairStatus lets the waiting page poll for approval without script
// that guesses.
func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.devices.Approved(deviceToken(r)) {
		_, _ = w.Write([]byte(`{"approved":true}`))
		return
	}
	_, _ = w.Write([]byte(`{"approved":false}`))
}

// handleHome renders the status and exposure view.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	status := s.cfg.Control.Status()
	peerID, nickname, _ := s.cfg.Control.Identity()

	s.render(w, r, "home.html", map[string]any{
		"Title":        "Your website",
		"Status":       status,
		"PeerID":       peerID,
		"Nickname":     nickname,
		"MeshHostname": s.cfg.Control.MeshHostname(),
		"Custom":       s.cfg.Control.CustomHostnames(),
		"Online":       len(status.ConnectedEdges) > 0,
		"Pending":      s.devices.Pending(),
		"Version":      version.Version,
	})
}

// handleRecovery shows the recovery key.
func (s *Server) handleRecovery(w http.ResponseWriter, r *http.Request) {
	key, err := recovery.Encode(s.cfg.Identity)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	_, nickname, _ := s.cfg.Control.Identity()
	s.render(w, r, "recovery.html", map[string]any{
		"Title":       "Recovery key",
		"RecoveryKey": key,
		"Nickname":    nickname,
	})
}

// handleDevices lists paired devices and anything waiting for approval.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "devices.html", map[string]any{
		"Title":   "Devices",
		"Devices": s.devices.Devices(),
		"Pending": s.devices.Pending(),
	})
}

// handleDeviceApprove admits a waiting device.
func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.FormValue("code"))
	if err := s.devices.Approve(code); err != nil {
		s.flashBack(w, r, "/devices", err.Error())
		return
	}
	s.log.Info("device approved")
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// handleDeviceRevoke removes a paired device.
func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	if err := s.devices.Revoke(strings.TrimSpace(r.FormValue("id"))); err != nil {
		s.flashBack(w, r, "/devices", err.Error())
		return
	}
	s.log.Info("device revoked")
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// handleDomains renders the custom-domain page.
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "domains.html", map[string]any{
		"Title":        "Your own domain",
		"Custom":       s.cfg.Control.CustomHostnames(),
		"MeshHostname": s.cfg.Control.MeshHostname(),
		"Error":        r.URL.Query().Get("error"),
	})
}

// handleDomainAdd starts serving a user-supplied domain.
func (s *Server) handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.FormValue("domain"))
	// People paste URLs. Accepting one and taking the hostname out of it is
	// less friction than telling them off for it.
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimSuffix(strings.SplitN(host, "/", 2)[0], ".")

	if err := s.cfg.Control.AddHostname(host); err != nil {
		s.flashBack(w, r, "/domains", err.Error())
		return
	}
	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}

// handleDomainRemove stops serving a user-supplied domain.
func (s *Server) handleDomainRemove(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Control.RemoveHostname(strings.TrimSpace(r.FormValue("domain"))); err != nil {
		s.flashBack(w, r, "/domains", err.Error())
		return
	}
	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}

// flashBack redirects with a human-readable error attached.
func (s *Server) flashBack(w http.ResponseWriter, r *http.Request, path, msg string) {
	http.Redirect(w, r, path+"?error="+url.QueryEscape(msg), http.StatusSeeOther)
}

// serverError logs and reports an unexpected failure.
//
// The message shown never includes the underlying error: the panel is on a
// home network where the audience for a stack trace is nobody.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("panel error", "path", r.URL.Path, "error", err)
	http.Error(w, "Something went wrong. The details are in the MeshMorphic log.", http.StatusInternalServerError)
}

// render writes a page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, page, data); err != nil {
		// A template failure part-way through a response cannot be turned into
		// a clean error page, so it is logged and the connection ends.
		s.log.Error("template failed", "page", page, "error", err)
	}
}

// describeDevice makes a short, human-recognisable label for a browser.
//
// The user-agent is attacker-controlled text that will be rendered on a page,
// so it is truncated and reduced to a coarse family name rather than shown
// verbatim. Templates escape it as well; this is the second layer.
func describeDevice(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	family := "Browser"
	switch {
	case strings.Contains(ua, "Firefox"):
		family = "Firefox"
	case strings.Contains(ua, "Edg/"):
		family = "Edge"
	case strings.Contains(ua, "Chrome"):
		family = "Chrome"
	case strings.Contains(ua, "Safari"):
		family = "Safari"
	}
	platform := "device"
	switch {
	case strings.Contains(ua, "Android"):
		platform = "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		platform = "iPhone or iPad"
	case strings.Contains(ua, "Mac OS"):
		platform = "Mac"
	case strings.Contains(ua, "Windows"):
		platform = "Windows"
	case strings.Contains(ua, "Linux"):
		platform = "Linux"
	}
	return family + " on " + platform
}

// newStaticHandler serves the embedded assets.
func newStaticHandler() (http.Handler, error) {
	sub, err := fsSub(assetsFS, "assets")
	if err != nil {
		return nil, err
	}
	return http.FileServer(http.FS(sub)), nil
}

// templateFuncs are the helpers available in templates.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"since": func(t time.Time) string {
			if t.IsZero() {
				return "not yet"
			}
			d := time.Since(t).Round(time.Minute)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%d minutes", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%d hours", int(d.Hours()))
			default:
				return fmt.Sprintf("%d days", int(d.Hours()/24))
			}
		},
	}
}
