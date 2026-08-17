// Command mm-gateway runs a MeshMorphic introduction service.
//
// A gateway is the easiest thing in this system to run and the least
// consequential to lose. It stores nothing about anyone, carries no website
// traffic, and holds no key that would decrypt any. Running one is a small
// favour to the network rather than a responsibility.
//
// Run several. They never need to know about each other's peers, so there is
// no cluster to build and nothing to keep in sync.
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
	"github.com/lightmorphic/meshmorphic/internal/gateway"
	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/proto"
	"github.com/lightmorphic/meshmorphic/internal/version"
)

func main() {
	var (
		listen       = flag.String("listen", ":7777", "UDP address for the QUIC introduction service")
		domains      = flag.String("domains", "awwwe.uk", "comma-separated DNS suffixes this network hands out")
		stateDir     = flag.String("state", "/var/lib/meshmorphic-gateway", "directory holding this gateway's identity")
		seeds        = flag.String("seeds", "", "other gateways to tell agents about: host:port|pubkey,...")
		statusListen = flag.String("status", "127.0.0.1:9440", "local address for the status endpoint, empty to disable")
		showID       = flag.Bool("identity", false, "print this gateway's identity and exit")
		publicAddr   = flag.String("public-addr", "", "the address others should dial, used only when printing the identity")
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
		cli.Fatal("could not load this gateway's identity: %v", err)
	}
	if created {
		log.Info("generated a new gateway identity", "id", id.ID())
	}
	if *showID {
		cli.PrintIdentity("gateway", id, *publicAddr)
		return
	}

	seedList, err := cli.ParsePeers(*seeds)
	if err != nil {
		cli.Fatal("could not read -seeds: %v", err)
	}
	gossip := make([]proto.GatewayInfo, 0, len(seedList))
	for _, s := range seedList {
		gossip = append(gossip, proto.GatewayInfo{
			GatewayID: identity.IDFromPublicKey(s.PubKey),
			PubKey:    identity.EncodeKey(s.PubKey),
			Addr:      s.Addr,
		})
	}

	srv, err := gateway.New(gateway.Config{
		Listen:   *listen,
		Domains:  cli.SplitList(*domains),
		Identity: id,
		Seeds:    gossip,
		Logger:   log,
	})
	if err != nil {
		cli.Fatal("could not start the gateway: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *statusListen != "" {
		go serveStatus(ctx, *statusListen, srv, log.Handler().Enabled(ctx, 0))
	}

	if err := srv.Run(ctx); err != nil {
		cli.Fatal("gateway stopped: %v", err)
	}
}

// serveStatus exposes aggregate counts for monitoring.
//
// Bound to loopback by default and carrying counts only. A gateway that
// published who was connected to it would become worth attacking, which is
// exactly what this design is trying to avoid.
func serveStatus(ctx context.Context, addr string, srv *gateway.Server, _ bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := srv.Stats()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"role":    "gateway",
			"version": version.Version,
			"edges":   stats.Edges,
			"agents":  stats.Agents,
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	s := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = s.Close() }()
	_ = s.ListenAndServe()
}
