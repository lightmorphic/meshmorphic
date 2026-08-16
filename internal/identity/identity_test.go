package identity

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
)

func TestIDDerivesFromKey(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !VerifyID(id.ID(), id.PublicKey) {
		t.Fatal("an identity's own ID must verify against its own key")
	}
	if !strings.HasPrefix(id.ID(), Prefix) {
		t.Fatalf("ID %q lacks the %q prefix", id.ID(), Prefix)
	}
}

// A peer that presents someone else's ID alongside its own key must be
// rejected. This is the check that makes identity self-certifying, and every
// authorisation decision downstream assumes it holds.
func TestVerifyIDRejectsMismatch(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	if VerifyID(a.ID(), b.PublicKey) {
		t.Fatal("an ID verified against a key it does not belong to")
	}
	if VerifyID("", a.PublicKey) {
		t.Fatal("an empty ID was accepted")
	}
	if VerifyID(a.ID(), ed25519.PublicKey(nil)) {
		t.Fatal("a nil key was accepted")
	}
	if VerifyID(a.ID(), a.PublicKey[:16]) {
		t.Fatal("a truncated key was accepted")
	}
}

// The host label is what an edge recomputes to decide whether a peer may serve
// a hostname. If two different keys could produce the same label, or if a
// label verified against the wrong key, hostname authorisation would collapse.
func TestHostLabel(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()

	if HostLabel(a.PublicKey) == HostLabel(b.PublicKey) {
		t.Fatal("two distinct keys produced the same host label")
	}
	if !VerifyHostLabel(HostLabel(a.PublicKey), a.PublicKey) {
		t.Fatal("a key failed to verify against its own label")
	}
	if VerifyHostLabel(HostLabel(a.PublicKey), b.PublicKey) {
		t.Fatal("a label verified against the wrong key")
	}
	// Case must not matter: DNS is case-insensitive and an edge may see a
	// hostname in any case.
	if !VerifyHostLabel(strings.ToUpper(HostLabel(a.PublicKey)), a.PublicKey) {
		t.Fatal("label verification is case-sensitive but DNS is not")
	}
}

func TestHostLabelIsDeterministicAndDNSSafe(t *testing.T) {
	id, _ := Generate()
	first := HostLabel(id.PublicKey)
	if first != HostLabel(id.PublicKey) {
		t.Fatal("host label is not deterministic")
	}
	if len(first) > 63 {
		t.Fatalf("host label %q is too long to be a DNS label", first)
	}
	for _, r := range first {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if !isLower && !isDigit {
			t.Fatalf("host label %q contains %q, which is not valid in a hostname", first, string(r))
		}
	}
}

// The label and the peer ID are derived from the same key but must not be the
// same value, or a leak of one would be a leak of the other's namespace.
func TestLabelAndIDAreDomainSeparated(t *testing.T) {
	id, _ := Generate()
	if strings.Contains(id.ID(), HostLabel(id.PublicKey)) {
		t.Fatal("the host label appears inside the peer ID; the derivations are not separated")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	original, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(path, original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ID() != original.ID() {
		t.Fatalf("round trip changed the identity: %s -> %s", original.ID(), loaded.ID())
	}
	if !loaded.PrivateKey.Equal(original.PrivateKey) {
		t.Fatal("round trip did not preserve the private key")
	}
}

func TestLoadOrCreateIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	first, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if !created {
		t.Fatal("the first call should report that it created an identity")
	}
	// Losing an identity on restart would lose the user their web address, so
	// this is worth asserting explicitly rather than assuming.
	second, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate (second): %v", err)
	}
	if created {
		t.Fatal("the second call created a new identity instead of loading the existing one")
	}
	if first.ID() != second.ID() {
		t.Fatal("the identity changed between runs")
	}
}

func TestEncodeDecodeKey(t *testing.T) {
	id, _ := Generate()
	decoded, err := DecodeKey(EncodeKey(id.PublicKey))
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !decoded.Equal(id.PublicKey) {
		t.Fatal("key did not survive the round trip")
	}
	for _, bad := range []string{"", "not base64!", "c2hvcnQ="} {
		if _, err := DecodeKey(bad); err == nil {
			t.Fatalf("DecodeKey accepted %q", bad)
		}
	}
}
