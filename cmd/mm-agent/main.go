// Command mm-agent runs MeshMorphic on a home server.
//
// It opens no ports. It dials outward to a gateway, learns which edges exist,
// opens a tunnel to each, and serves the local website over them. TLS
// terminates in this process, on this machine, with a key that is generated
// here and never sent anywhere.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lightmorphic/meshmorphic/internal/agent"
	"github.com/lightmorphic/meshmorphic/internal/cli"
	"github.com/lightmorphic/meshmorphic/internal/identity"
	"github.com/lightmorphic/meshmorphic/internal/panel"
	"github.com/lightmorphic/meshmorphic/internal/recovery"
	"github.com/lightmorphic/meshmorphic/internal/version"
)

const usage = `MeshMorphic agent ` + version.Version + `

  mm-agent run                 serve the website (the default)
  mm-agent status              show whether the site is online
  mm-agent identity            show this computer's identity
  mm-agent recovery            show the recovery key to write down
  mm-agent restore <key>       replace this computer's identity from a recovery key
  mm-agent devices approve <code>
  mm-agent devices reset       forget every approved device

Options are read from the config file and can be overridden with flags.
Run "mm-agent run -h" for the full list.
`

func main() {
	if len(os.Args) < 2 {
		runAgent(nil)
		return
	}
	switch os.Args[1] {
	case "run":
		runAgent(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "identity":
		cmdIdentity(os.Args[2:])
	case "recovery":
		cmdRecovery(os.Args[2:])
	case "restore":
		cmdRestore(os.Args[2:])
	case "devices":
		cmdDevices(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	case "-version", "--version", "version":
		fmt.Println(version.Version)
	default:
		// A bare invocation with flags should still just run.
		if strings.HasPrefix(os.Args[1], "-") {
			runAgent(os.Args[1:])
			return
		}
		fmt.Print(usage)
		os.Exit(1)
	}
}

// Config is the agent's on-disk configuration.
//
// It is deliberately short. Everything a nervous person could be asked at
// install time is either derived, defaulted, or set later in the panel; this
// file exists so that a machine can be rebuilt from it, not so that anybody
// has to write one.
type Config struct {
	Gateways        []ConfigPeer `json:"gateways"`
	Upstream        string       `json:"upstream"`
	StateDir        string       `json:"state_dir"`
	SiteDir         string       `json:"site_dir"`
	PanelListen     string       `json:"panel_listen"`
	CustomHostnames []string     `json:"custom_hostnames"`
	ACMEEmail       string       `json:"acme_email"`
	ACMEStaging     bool         `json:"acme_staging"`
}

// ConfigPeer is an address paired with the key expected to answer at it.
type ConfigPeer struct {
	Addr   string `json:"addr"`
	PubKey string `json:"pubkey"`
}

const defaultConfigPath = "/etc/meshmorphic/agent.json"

func defaults() Config {
	return Config{
		Upstream:    "http://127.0.0.1:8080",
		StateDir:    "/var/lib/meshmorphic",
		SiteDir:     "/var/lib/meshmorphic/site",
		PanelListen: "0.0.0.0:8800",
	}
}

// loadConfig reads the configuration, falling back to defaults.
func loadConfig(path string) (Config, error) {
	cfg := defaults()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("could not read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("could not understand %s: %w", path, err)
	}
	return cfg, nil
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		configPath  = fs.String("config", defaultConfigPath, "configuration file")
		gateways    = fs.String("gateways", "", "override the gateways: host:port|pubkey,...")
		upstream    = fs.String("upstream", "", "override the local website address")
		panelListen = fs.String("panel", "", "override the settings panel address")
		staging     = fs.Bool("acme-staging", false, "use Let's Encrypt staging (untrusted certificates, generous limits)")
		debug       = fs.Bool("debug", false, "verbose logging")
	)
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		cli.Fatal("%v", err)
	}
	if *upstream != "" {
		cfg.Upstream = *upstream
	}
	if *panelListen != "" {
		cfg.PanelListen = *panelListen
	}
	if *staging {
		cfg.ACMEStaging = true
	}

	log := cli.Logger(*debug)

	targets, err := resolveGateways(cfg, *gateways)
	if err != nil {
		cli.Fatal("%v", err)
	}
	if len(targets) == 0 {
		cli.Fatal("no gateways configured. Set them in %s or pass -gateways host:port|pubkey", *configPath)
	}

	id, created, err := identity.LoadOrCreate(filepath.Join(cfg.StateDir, "identity.json"))
	if err != nil {
		cli.Fatal("could not load this computer's identity: %v", err)
	}
	if created {
		log.Info("generated a new identity for this computer", "id", id.ID())
	}

	if err := os.MkdirAll(cfg.SiteDir, 0o755); err != nil {
		cli.Fatal("could not create the website directory: %v", err)
	}

	ag, err := agent.New(agent.Config{
		Identity:        id,
		Gateways:        targets,
		Upstream:        cfg.Upstream,
		CertDir:         filepath.Join(cfg.StateDir, "certs"),
		CustomHostnames: cfg.CustomHostnames,
		ACMEEmail:       cfg.ACMEEmail,
		ACMEStaging:     cfg.ACMEStaging,
		Logger:          log,
	})
	if err != nil {
		cli.Fatal("could not start: %v", err)
	}

	pnl, err := panel.New(panel.Config{
		Listen:   cfg.PanelListen,
		StateDir: cfg.StateDir,
		SiteDir:  cfg.SiteDir,
		Identity: id,
		Control:  controller{ag},
		Logger:   log,
	})
	if err != nil {
		cli.Fatal("could not start the settings panel: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := pnl.Run(ctx); err != nil {
			log.Error("settings panel stopped", "error", err)
		}
	}()
	go func() {
		if err := pnl.RunControlSocket(ctx, filepath.Join(cfg.StateDir, "control.sock")); err != nil {
			log.Error("control socket stopped", "error", err)
		}
	}()

	if err := ag.Run(ctx); err != nil {
		cli.Fatal("stopped: %v", err)
	}
}

// resolveGateways merges the configured gateways with any flag override.
func resolveGateways(cfg Config, override string) ([]agent.GatewayTarget, error) {
	if override != "" {
		peers, err := cli.ParsePeers(override)
		if err != nil {
			return nil, fmt.Errorf("could not read -gateways: %w", err)
		}
		out := make([]agent.GatewayTarget, 0, len(peers))
		for _, p := range peers {
			out = append(out, agent.GatewayTarget{Addr: p.Addr, PubKey: p.PubKey})
		}
		return out, nil
	}
	out := make([]agent.GatewayTarget, 0, len(cfg.Gateways))
	for _, g := range cfg.Gateways {
		pub, err := identity.DecodeKey(g.PubKey)
		if err != nil {
			return nil, fmt.Errorf("the public key for gateway %s is not usable: %w", g.Addr, err)
		}
		out = append(out, agent.GatewayTarget{Addr: g.Addr, PubKey: pub})
	}
	return out, nil
}

// controller adapts the agent to the narrow interface the panel is given.
type controller struct{ ag *agent.Agent }

func (c controller) Status() panel.Status {
	s := c.ag.Status()
	return panel.Status{
		PeerID:         s.PeerID,
		Nickname:       s.Nickname,
		Hostnames:      s.Hostnames,
		GatewayID:      s.GatewayID,
		ConnectedEdges: s.ConnectedEdge,
		Since:          s.Since,
		LastError:      s.LastError,
	}
}

func (c controller) Identity() (string, string, string) { return c.ag.Identity() }
func (c controller) MeshHostname() string               { return c.ag.MeshHostname() }
func (c controller) CustomHostnames() []string          { return c.ag.CustomHostnames() }
func (c controller) AddHostname(h string) error         { return c.ag.AddHostname(h) }
func (c controller) RemoveHostname(h string) error      { return c.ag.RemoveHostname(h) }

func cmdIdentity(args []string) {
	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		cli.Fatal("%v", err)
	}
	id, err := identity.Load(filepath.Join(cfg.StateDir, "identity.json"))
	if err != nil {
		cli.Fatal("could not load this computer's identity: %v", err)
	}
	cli.PrintIdentity("agent", id, "")
	fmt.Printf("  address: %s.<mesh domain>\n", identity.HostLabel(id.PublicKey))
}

func cmdRecovery(args []string) {
	fs := flag.NewFlagSet("recovery", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		cli.Fatal("%v", err)
	}
	id, err := identity.Load(filepath.Join(cfg.StateDir, "identity.json"))
	if err != nil {
		cli.Fatal("could not load this computer's identity: %v", err)
	}
	key, err := recovery.Encode(id)
	if err != nil {
		cli.Fatal("%v", err)
	}
	fmt.Println("Write this down on paper and keep it somewhere safe.")
	fmt.Println("Nobody else has a copy. If this computer dies and you have not")
	fmt.Println("written it down, this web address cannot be recovered by anyone.")
	fmt.Printf("\n  %s\n\n", key)
}

func cmdRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	force := fs.Bool("force", false, "replace an existing identity")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		cli.Fatal("usage: mm-agent restore <recovery key>")
	}
	// A key read off paper arrives as several arguments once the shell has
	// split it on spaces. Rejoining is friendlier than insisting on quotes.
	key := strings.Join(fs.Args(), "")

	cfg, err := loadConfig(*configPath)
	if err != nil {
		cli.Fatal("%v", err)
	}
	restored, err := recovery.Decode(key)
	if err != nil {
		cli.Fatal("%v", err)
	}

	path := filepath.Join(cfg.StateDir, "identity.json")
	if existing, err := identity.Load(path); err == nil {
		if existing.ID() == restored.ID() {
			fmt.Println("This computer already has that identity. Nothing to do.")
			return
		}
		if !*force {
			cli.Fatal("this computer already has a different identity (%s).\n"+
				"Restoring would abandon its current web address.\n"+
				"Re-run with -force if that is what you want.", existing.ID())
		}
	}
	if err := identity.Save(path, restored); err != nil {
		cli.Fatal("could not save the restored identity: %v", err)
	}
	fmt.Printf("Restored. This computer is now %s\n", restored.ID())
	fmt.Printf("Its address will be %s.<mesh domain>\n", identity.HostLabel(restored.PublicKey))
	fmt.Println("Restart MeshMorphic for this to take effect.")
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		cli.Fatal("%v", err)
	}
	body, err := controlRequest(cfg, "GET", "/status", nil)
	if err != nil {
		cli.Fatal("%v", err)
	}

	var st struct {
		Nickname       string   `json:"nickname"`
		MeshHostname   string   `json:"mesh_hostname"`
		CustomDomains  []string `json:"custom_domains"`
		ConnectedEdges []string `json:"connected_edges"`
		Online         bool     `json:"online"`
		LastError      string   `json:"last_error"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		cli.Fatal("could not read the reply from MeshMorphic: %v", err)
	}

	if st.Online {
		fmt.Printf("Online  ✓\n")
	} else {
		fmt.Printf("Offline !\n")
	}
	if st.MeshHostname != "" {
		fmt.Printf("Address     https://%s\n", st.MeshHostname)
	}
	fmt.Printf("Nickname    %s\n", st.Nickname)
	for _, d := range st.CustomDomains {
		fmt.Printf("Also        https://%s\n", d)
	}
	fmt.Printf("Entry points %d\n", len(st.ConnectedEdges))
	if st.LastError != "" {
		fmt.Printf("Last problem %s\n", st.LastError)
	}
}

func cmdDevices(args []string) {
	if len(args) == 0 {
		cli.Fatal("usage: mm-agent devices approve <code>  |  mm-agent devices reset")
	}
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	_ = fs.Parse(args[1:])

	cfg, err := loadConfig(*configPath)
	if err != nil {
		cli.Fatal("%v", err)
	}

	switch args[0] {
	case "approve":
		if fs.NArg() < 1 {
			cli.Fatal("usage: mm-agent devices approve <code>")
		}
		form := "code=" + strings.TrimSpace(fs.Arg(0))
		if _, err := controlRequest(cfg, "POST", "/devices/approve", strings.NewReader(form)); err != nil {
			cli.Fatal("%v", err)
		}
		fmt.Println("Approved. That device can now open the settings panel.")
	case "reset":
		if _, err := controlRequest(cfg, "POST", "/devices/reset", nil); err != nil {
			cli.Fatal("%v", err)
		}
		fmt.Println("All devices removed. The next browser to open the panel becomes the owner.")
	default:
		cli.Fatal("unknown devices command %q", args[0])
	}
}
