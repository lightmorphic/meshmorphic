package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// controlRequest talks to the running agent over its unix control socket.
//
// Using a socket rather than reading the state files directly matters: the
// running process holds device approvals in memory as well as on disk, and two
// processes editing the same file would race. Asking the owner of that state
// is both simpler and correct.
func controlRequest(cfg Config, method, path string, body io.Reader) ([]byte, error) {
	socket := filepath.Join(cfg.StateDir, "control.sock")
	if _, err := os.Stat(socket); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("MeshMorphic does not appear to be running (no control socket at %s)", socket)
		}
		return nil, err
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}

	// The host in the URL is ignored by the unix dialler but has to be
	// something valid for the request to be constructible.
	req, err := http.NewRequest(method, "http://meshmorphic"+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return nil, fmt.Errorf("not permitted to talk to MeshMorphic. Try again with sudo")
		}
		return nil, fmt.Errorf("could not reach MeshMorphic: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, errors.New(e.Error)
		}
		return nil, fmt.Errorf("MeshMorphic returned %s", resp.Status)
	}
	return raw, nil
}
