// Package cli holds helpers shared by the three MeshMorphic binaries.
package cli

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
)

// Peer is an address paired with the public key expected at it.
//
// The two always travel together. An address on its own is not a usable
// destination in this system, because dialling somewhere without knowing which
// key should answer is the thing MeshMorphic refuses to do.
type Peer struct {
	Addr   string
	PubKey ed25519.PublicKey
}

// ParsePeers reads a comma-separated list of "host:port|base64key" entries.
func ParsePeers(s string) ([]Peer, error) {
	var out []Peer
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, key, ok := strings.Cut(item, "|")
		if !ok {
			return nil, fmt.Errorf("cli: %q should be host:port|publickey", item)
		}
		pub, err := identity.DecodeKey(key)
		if err != nil {
			return nil, fmt.Errorf("cli: public key for %s: %w", addr, err)
		}
		out = append(out, Peer{Addr: strings.TrimSpace(addr), PubKey: pub})
	}
	return out, nil
}

// SplitList parses a comma-separated list, dropping blanks.
func SplitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Logger builds the standard logger. Text rather than JSON: these logs are
// read by people running one machine, not shipped to a log aggregator.
func Logger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// Fatal prints a message and exits non-zero.
func Fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// PrintIdentity writes the details an operator needs to publish so others can
// reach this node.
//
// The public key is not optional decoration. Every peer that connects here
// pins it, so a node's address is meaningless without it. Printing them
// together makes it hard to publish one and forget the other.
func PrintIdentity(role string, id *identity.Identity, addr string) {
	fmt.Printf("%s identity\n", role)
	fmt.Printf("  id:      %s\n", id.ID())
	fmt.Printf("  pubkey:  %s\n", identity.EncodeKey(id.PublicKey))
	if addr != "" {
		fmt.Printf("\nOthers reach this %s with:\n  %s|%s\n", role, addr, identity.EncodeKey(id.PublicKey))
	}
}
