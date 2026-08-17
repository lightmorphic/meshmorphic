// Command mm-edge runs a MeshMorphic ingress node.
//
// An edge accepts visitors' connections on behalf of home servers and passes
// the bytes through without being able to read them. It holds no certificate
// and no certificate key, so running one does not put the operator in
// possession of anybody's traffic.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lightmorphic/meshmorphic/internal/cli"
	"github.com/lightmorphic/meshmorphic/internal/edge"
	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/version"
)

func main() {
	var (
		tunnelListen = flag.String("tunnel", ":7443", "UDP address agents dial for their tunnel")
		httpsListen  = flag.String("https", ":443", "TCP address for visitor HTTPS traffic")
		httpListen   = flag.String("http", ":80", "TCP address for visitor HTTP traffic")
		meshDomains  = flag.String("domains", "awwe.uk", "comma-separated mesh domains this edge serves")
		gateways     = flag.String("gateways", "", "gateways to announce to: host:port|pubkey,...")
		publicAddr   = flag.String("public-addr", "", "the address agents should dial for the tunnel, e.g. edge1.awwe.uk:7443")
		allowCustom  = flag.Bool("allow-custom-domains", true, "serve domains outside the mesh domains when an agent claims one")
		stateDir     = flag.String("state", "/var/lib/meshmorphic-edge", "directory holding this edge's identity")
		statusListen = flag.String("status", "127.0.0.1:9441", "local address for the status endpoint, empty to disable")
		showID       = flag.Bool("identity", false, "print this edge's identity and exit")
		debug        = flag.Bool("debug", false, "verbose logging")
		showVersion  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	log := cli.Logger(*debug)

	id, created, err := identity.LoadOrCreate(filepath.Join(*stateDir, "identity.json"))
	if err != nil {
		cli.Fatal("could not load this edge's identity: %v", err)
	}
	if created {
		log.Info("generated a new edge identity", "id", id.ID())
	}
	if *showID {
		cli.PrintIdentity("edge", id, *publicAddr)
		return
	}

	srv, err := edge.New(edge.Config{
		TunnelListen:       *tunnelListen,
		HTTPSListen:        *httpsListen,
		HTTPListen:         *httpListen,
		MeshDomains:        cli.SplitList(*meshDomains),
		AllowCustomDomains: *allowCustom,
		Identity:           id,
		Logger:             log,
	})
	if err != nil {
		cli.Fatal("could not start the edge: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targets, err := cli.ParsePeers(*gateways)
	if err != nil {
		cli.Fatal("could not read -gateways: %v", err)
	}
	if len(targets) == 0 {
		// An edge with no gateway still serves the agents that already know
		// it, but no new agent will ever be told it exists.
		log.Warn("no gateways configured; agents will not discover this edge")
	}
	if len(targets) > 0 && *publicAddr == "" {
		cli.Fatal("-public-addr is required when announcing to gateways: agents need an address to dial")
	}
	for _, t := range targets {
		go srv.Announce(ctx, edge.GatewayTarget{Addr: t.Addr, PubKey: t.PubKey}, *publicAddr)
	}

	if *statusListen != "" {
		go serveStatus(ctx, *statusListen, srv)
	}

	if err := srv.Run(ctx); err != nil {
		cli.Fatal("edge stopped: %v", err)
	}
}

// serveStatus exposes aggregate counts for monitoring, with no hostnames or
// identities in the output.
func serveStatus(ctx context.Context, addr string, srv *edge.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"role":    "edge",
			"version": version.Version,
			"routes":  srv.Stats().Routes,
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	s := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = s.Close() }()
	_ = s.ListenAndServe()
}
