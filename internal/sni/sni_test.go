package sni

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHelloFor produces a genuine ClientHello by running a real TLS client
// against a pipe, then peeks it. Hand-rolled fixtures would drift from what
// browsers actually send; this stays honest because crypto/tls generates it.
func clientHelloFor(t *testing.T, serverName string, conf func(*tls.Config)) (string, []byte, error) {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close(); _ = serverSide.Close() })

	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
	if conf != nil {
		conf(cfg)
	}
	go func() {
		// The handshake never completes: nothing answers. It only needs to get
		// as far as writing the ClientHello.
		_ = tls.Client(clientSide, cfg).Handshake()
	}()

	return Peek(serverSide)
}

func TestPeekFindsServerName(t *testing.T) {
	const want = "qz3k9rf7dnxb2wp8sq4t.awwwe.uk"

	got, consumed, err := clientHelloFor(t, want, nil)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if got != want {
		t.Fatalf("got server name %q, want %q", got, want)
	}
	if len(consumed) == 0 {
		t.Fatal("Peek consumed bytes but returned none for replay")
	}
	if consumed[0] != 0x16 {
		t.Fatalf("replay bytes do not start with a TLS handshake record: %#x", consumed[0])
	}
}

// The bytes handed back must be exactly what arrived, because the edge replays
// them to the home server. Anything lost or reordered here breaks the
// handshake in a way that would be maddening to diagnose.
func TestPeekReplayIsTheCompleteClientHello(t *testing.T) {
	_, consumed, err := clientHelloFor(t, "example.awwwe.uk", nil)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	// Record header is 5 bytes; the declared body length must match what
	// follows it, proving nothing was truncated.
	if len(consumed) < 5 {
		t.Fatalf("replay is only %d bytes", len(consumed))
	}
	declared := int(consumed[3])<<8 | int(consumed[4])
	if got := len(consumed) - 5; got != declared {
		t.Fatalf("record declares %d body bytes but %d were captured", declared, got)
	}
}

func TestPeekHandlesLongNamesAndALPN(t *testing.T) {
	// A browser sends a long ALPN list and several extensions, which pushes
	// server_name away from the start of the extension block.
	want := strings.Repeat("a", 60) + ".awwwe.uk"
	got, _, err := clientHelloFor(t, want, func(c *tls.Config) {
		c.NextProtos = []string{"h2", "http/1.1", "acme-tls/1"}
	})
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A connection with no server name cannot be routed, and must be refused
// rather than guessed at. Scanners hitting the edge's bare IP land here.
func TestPeekWithoutServerName(t *testing.T) {
	// An IP literal as ServerName means crypto/tls omits the SNI extension.
	_, _, err := clientHelloFor(t, "203.0.113.10", nil)
	if !errors.Is(err, ErrNoSNI) {
		t.Fatalf("expected ErrNoSNI, got %v", err)
	}
}

func TestPeekRejectsNonTLS(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	_, _, err := Peek(server)
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("expected ErrNotTLS for a plain HTTP request, got %v", err)
	}
}

// Malformed input arrives from unauthenticated strangers, so the parser must
// fail rather than panic. A panic here would be a remote denial of service
// against every site behind the edge.
func TestPeekSurvivesMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"truncated record header": {0x16, 0x03, 0x01},
		"zero length record":      {0x16, 0x03, 0x01, 0x00, 0x00},
		"lying length":            {0x16, 0x03, 0x01, 0xff, 0xff, 0x01},
		"handshake type wrong":    {0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		"truncated client hello":  {0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0xff, 0xff},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close(); _ = server.Close() }()

			go func() {
				_, _ = client.Write(payload)
				_ = client.Close()
			}()

			done := make(chan struct{})
			go func() {
				defer close(done)
				// The assertion is simply that this returns at all, with an
				// error, and without panicking.
				if _, _, err := Peek(server); err == nil {
					t.Errorf("malformed input was accepted")
				}
			}()
			select {
			case <-done:
			case <-time.After(PeekTimeout + 5*time.Second):
				t.Fatal("Peek did not return")
			}
		})
	}
}

func TestPeekRefusesOversizedHello(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()

	go func() {
		// Declare a record far larger than any real ClientHello.
		_, _ = client.Write([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
		_, _ = io.Copy(client, io.LimitReader(neverEnding{}, 1<<20))
		_ = client.Close()
	}()

	if _, _, err := Peek(server); err == nil {
		t.Fatal("an oversized record was accepted")
	}
}

// neverEnding produces endless zero bytes.
type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
