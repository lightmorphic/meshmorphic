package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The control socket is how the command line reaches the running agent.
//
// It exists because approving a device is a decision made in one process
// (someone typing on the machine) about state held in another (the running
// panel). Rather than have two processes share a file and race, the CLI simply
// asks the agent.
//
// Authorisation is the socket's file permissions. It lives in the agent's own
// state directory with mode 0600, so being able to talk to it already means
// having the agent's own privileges on the machine — at which point there is
// nothing left to protect. That is a stronger boundary than a token, and it
// cannot be phished.

// ControlHandler builds the handler served on the control socket.
func (s *Server) ControlHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		status := s.cfg.Control.Status()
		peerID, nickname, hostLabel := s.cfg.Control.Identity()
		writeJSON(w, map[string]any{
			"peer_id":         peerID,
			"nickname":        nickname,
			"host_label":      hostLabel,
			"mesh_hostname":   s.cfg.Control.MeshHostname(),
			"custom_domains":  s.cfg.Control.CustomHostnames(),
			"connected_edges": status.ConnectedEdges,
			"gateway_id":      status.GatewayID,
			"online":          len(status.ConnectedEdges) > 0,
			"since":           status.Since,
			"last_error":      status.LastError,
		})
	})

	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"devices": s.devices.Devices(),
			"pending": s.devices.Pending(),
		})
	})

	mux.HandleFunc("POST /devices/approve", func(w http.ResponseWriter, r *http.Request) {
		code := strings.TrimSpace(r.FormValue("code"))
		if err := s.devices.Approve(code); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.log.Info("device approved from the command line")
		writeJSON(w, map[string]any{"approved": true})
	})

	mux.HandleFunc("POST /devices/reset", func(w http.ResponseWriter, r *http.Request) {
		if err := s.devices.Reset(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.log.Warn("all panel devices removed; the next browser to connect becomes the owner")
		writeJSON(w, map[string]any{"reset": true})
	})

	return mux
}

// maxSocketPath is the longest usable unix socket path. Linux allows 108
// bytes including the terminator; the margin here keeps it portable.
const maxSocketPath = 100

// RunControlSocket serves the control API on a unix socket until ctx ends.
func (s *Server) RunControlSocket(ctx context.Context, path string) error {
	// Unix socket paths are limited by the kernel's sockaddr_un.sun_path, which
	// is 108 bytes on Linux and less elsewhere. Exceeding it fails with a bare
	// "invalid argument" that tells the operator nothing, so it is caught here
	// with an explanation of what to actually change.
	if len(path) > maxSocketPath {
		return fmt.Errorf("panel: the control socket path is %d characters, which is over the %d the "+
			"operating system allows. Set a shorter state_dir in the configuration: %s",
			len(path), maxSocketPath, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("panel: create control socket directory: %w", err)
	}
	// A socket left behind by a previous run would prevent binding. Removing
	// it is safe: the directory is the agent's own and mode 0700.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("panel: clear stale control socket: %w", err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("panel: listen on control socket: %w", err)
	}
	// Set the mode after binding: the umask applies at creation, so relying on
	// it would leave the socket briefly more permissive than intended.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("panel: secure control socket: %w", err)
	}

	srv := &http.Server{
		Handler:           s.ControlHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = os.Remove(path)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("panel: control socket: %w", err)
	}
	return nil
}

// Reset removes every enrolled device, so the next browser becomes the owner.
func (s *deviceStore) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = nil
	s.pending = make(map[string]*pendingRequest)
	return s.saveLocked()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
