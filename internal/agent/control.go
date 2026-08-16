package agent

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
	"github.com/FOSSCharlie/meshmorphic/internal/names"
)

// This file is the surface the settings panel drives the agent through. It is
// intentionally narrow: the panel can ask what is happening and add or remove
// a custom domain, and that is all. It cannot reach the identity key, the
// tunnels, or the certificate store.

// Identity exposes the agent's public identity for display.
//
// It returns the peer ID and public key only. The private key is never handed
// out, so no amount of confusion in the panel can result in it being rendered
// into a page.
func (a *Agent) Identity() (peerID, nickname, hostLabel string) {
	return a.cfg.Identity.ID(),
		names.Nickname(a.cfg.Identity.PublicKey),
		identity.HostLabel(a.cfg.Identity.PublicKey)
}

// MeshHostname returns the automatic address derived from this agent's key.
func (a *Agent) MeshHostname() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	label := identity.HostLabel(a.cfg.Identity.PublicKey)
	for h := range a.hostnames {
		if l, _, ok := cutLabel(h); ok && l == label {
			return h
		}
	}
	return ""
}

// CustomHostnames lists the domains the user has added.
func (a *Agent) CustomHostnames() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	mesh := identity.HostLabel(a.cfg.Identity.PublicKey)
	out := make([]string, 0, len(a.hostnames))
	for h := range a.hostnames {
		if l, _, ok := cutLabel(h); ok && l == mesh {
			continue
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// ErrInvalidHostname means the text is not usable as a domain name.
var ErrInvalidHostname = errors.New("that does not look like a domain name")

// AddHostname starts serving a user-supplied domain.
//
// The name is validated before it goes anywhere near a certificate request:
// autocert asks this agent whether a name is allowed, and a malformed entry
// here would turn into a failed ACME order and, repeated, a rate-limit block
// on the real domain.
func (a *Agent) AddHostname(host string) error {
	host = normalizeHost(host)
	if err := validateHostname(host); err != nil {
		return err
	}
	// A user cannot add a name under the mesh domain by hand: those are
	// derived from keys, and one typed in here would be refused by every edge
	// anyway. Saying so now is kinder than a silent failure later.
	if label := identity.HostLabel(a.cfg.Identity.PublicKey); strings.HasPrefix(host, label+".") {
		return errors.New("that is already your automatic address")
	}

	a.mu.Lock()
	if a.hostnames[host] {
		a.mu.Unlock()
		return nil
	}
	a.hostnames[host] = true
	a.mu.Unlock()

	a.setStatus(func(s *Status) { s.Hostnames = a.hostnameList() })
	a.log.Info("now serving an additional domain", "host", host)
	a.notifyReclaim()
	return nil
}

// RemoveHostname stops serving a user-supplied domain.
func (a *Agent) RemoveHostname(host string) error {
	host = normalizeHost(host)
	label := identity.HostLabel(a.cfg.Identity.PublicKey)
	if strings.HasPrefix(host, label+".") {
		return errors.New("the automatic address cannot be removed")
	}
	a.mu.Lock()
	delete(a.hostnames, host)
	a.mu.Unlock()
	a.setStatus(func(s *Status) { s.Hostnames = a.hostnameList() })
	a.log.Info("stopped serving a domain", "host", host)
	a.notifyReclaim()
	return nil
}

// validateHostname applies the rules a public certificate authority will
// apply, so a bad name fails here with an explanation rather than there with
// an error code.
func validateHostname(host string) error {
	if host == "" {
		return ErrInvalidHostname
	}
	if len(host) > 253 {
		return fmt.Errorf("%w: it is too long", ErrInvalidHostname)
	}
	if strings.HasPrefix(host, "*") {
		return fmt.Errorf("%w: wildcard domains are not supported", ErrInvalidHostname)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: it needs at least one dot, like example.com", ErrInvalidHostname)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%w: %q is not a usable part of a domain", ErrInvalidHostname, l)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("%w: parts cannot start or end with a dash", ErrInvalidHostname)
		}
		for _, r := range l {
			isLetter := r >= 'a' && r <= 'z'
			isDigit := r >= '0' && r <= '9'
			if !isLetter && !isDigit && r != '-' {
				return fmt.Errorf("%w: %q contains characters that are not allowed", ErrInvalidHostname, l)
			}
		}
	}
	// A bare public suffix cannot be certified and is almost always a typo.
	if labels[len(labels)-1] == "local" {
		return fmt.Errorf("%w: .local names cannot be given a public certificate", ErrInvalidHostname)
	}
	return nil
}

// EdgeCount reports how many edges currently hold a tunnel to this agent.
func (a *Agent) EdgeCount() int {
	a.statusMu.RLock()
	defer a.statusMu.RUnlock()
	return len(a.status.ConnectedEdge)
}
