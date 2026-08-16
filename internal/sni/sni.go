// Package sni extracts the server name from a TLS ClientHello without
// terminating the connection.
//
// This is what lets an edge route a visitor to the right home server while
// remaining unable to read anything. The ClientHello is the one part of a TLS
// session that travels in the clear, and the server name is the only field
// read here. Everything after it stays ciphertext that the edge forwards
// untouched and cannot decrypt, because the certificate's private key exists
// only on the home machine.
//
// The bytes consumed while reading are handed back to the caller so they can
// be replayed to the origin. Nothing is lost and nothing is reordered: the
// origin sees the exact ClientHello the browser sent.
package sni

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Limits sized against reality: a ClientHello with a long ALPN list and
// post-quantum key shares is a few kilobytes, never sixteen.
const (
	maxHandshake  = 16 << 10
	maxRecords    = 8
	recordHeader  = 5
	handshakeHead = 4
	// PeekTimeout bounds how long a connection may sit having sent nothing.
	// A visitor's browser sends its ClientHello immediately; anything slower
	// is a scanner or a stalled socket and should not hold a slot open.
	PeekTimeout = 10 * time.Second
)

// ErrNoSNI means a well-formed ClientHello carried no server name. Direct
// connections to the edge's IP address land here, and are refused: the edge
// has no way to know where such a connection was meant to go.
var ErrNoSNI = errors.New("sni: ClientHello contains no server name")

// ErrNotTLS means the first byte was not a TLS handshake record.
var ErrNotTLS = errors.New("sni: not a TLS handshake")

// Peek reads the ClientHello from conn, returning the server name and every
// byte consumed so the caller can replay them.
//
// The consumed bytes are returned even on error, so a caller that wants to
// forward a connection it could not classify still can.
func Peek(conn net.Conn) (name string, consumed []byte, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(PeekTimeout)); err != nil {
		return "", nil, fmt.Errorf("sni: set read deadline: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var raw []byte       // every byte read from the wire, for replay
	var handshake []byte // handshake payload with record framing stripped

	for range maxRecords {
		hdr := make([]byte, recordHeader)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return "", raw, fmt.Errorf("sni: read record header: %w", err)
		}
		raw = append(raw, hdr...)

		if hdr[0] != 0x16 { // handshake content type
			return "", raw, ErrNotTLS
		}
		length := int(hdr[3])<<8 | int(hdr[4])
		if length == 0 || length > maxHandshake {
			return "", raw, fmt.Errorf("sni: implausible record length %d", length)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", raw, fmt.Errorf("sni: read record body: %w", err)
		}
		raw = append(raw, body...)
		handshake = append(handshake, body...)

		if len(handshake) > maxHandshake {
			return "", raw, errors.New("sni: ClientHello is implausibly large")
		}
		// Do we have the whole handshake message yet? A ClientHello split
		// across records is rare but legal, so keep reading until it is whole.
		if len(handshake) >= handshakeHead {
			want := handshakeHead + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
			if len(handshake) >= want {
				name, err := parseClientHello(handshake[:want])
				return name, raw, err
			}
		}
	}
	return "", raw, errors.New("sni: ClientHello did not complete within the record limit")
}

// parseClientHello walks a complete handshake message to the server_name
// extension. It is written as a sequence of explicitly bounds-checked reads
// because it is the only code in the project that parses attacker-controlled
// bytes before any authentication has happened.
func parseClientHello(b []byte) (string, error) {
	if len(b) < handshakeHead || b[0] != 0x01 { // client_hello
		return "", ErrNotTLS
	}
	p := newParser(b[handshakeHead:])

	if !p.skip(2 + 32) { // legacy_version + random
		return "", errShort
	}
	if !p.skipVector(1) { // legacy_session_id
		return "", errShort
	}
	if !p.skipVector(2) { // cipher_suites
		return "", errShort
	}
	if !p.skipVector(1) { // legacy_compression_methods
		return "", errShort
	}

	exts, ok := p.vector(2)
	if !ok {
		// No extension block at all: a TLS 1.0-era hello. Valid, but nothing
		// here can be routed.
		return "", ErrNoSNI
	}
	ep := newParser(exts)
	for ep.remaining() >= 4 {
		extType, ok := ep.uint16()
		if !ok {
			return "", errShort
		}
		extBody, ok := ep.vector(2)
		if !ok {
			return "", errShort
		}
		if extType != 0x0000 { // server_name
			continue
		}
		return parseServerNameList(extBody)
	}
	return "", ErrNoSNI
}

// parseServerNameList reads the ServerNameList, returning the first
// host_name entry.
func parseServerNameList(b []byte) (string, error) {
	p := newParser(b)
	list, ok := p.vector(2)
	if !ok {
		return "", errShort
	}
	lp := newParser(list)
	for lp.remaining() >= 3 {
		nameType, ok := lp.uint8()
		if !ok {
			return "", errShort
		}
		host, ok := lp.vector(2)
		if !ok {
			return "", errShort
		}
		if nameType == 0 { // host_name
			if len(host) == 0 {
				return "", ErrNoSNI
			}
			return string(host), nil
		}
	}
	return "", ErrNoSNI
}

var errShort = errors.New("sni: ClientHello is malformed or truncated")

// parser is a bounds-checked cursor over a byte slice. Every method returns
// false rather than panicking, so malformed input from an unauthenticated
// stranger fails as a refused connection instead of a crashed edge.
type parser struct {
	b []byte
	i int
}

func newParser(b []byte) *parser { return &parser{b: b} }

func (p *parser) remaining() int { return len(p.b) - p.i }

func (p *parser) skip(n int) bool {
	if n < 0 || p.remaining() < n {
		return false
	}
	p.i += n
	return true
}

func (p *parser) uint8() (uint8, bool) {
	if p.remaining() < 1 {
		return 0, false
	}
	v := p.b[p.i]
	p.i++
	return v, true
}

func (p *parser) uint16() (uint16, bool) {
	if p.remaining() < 2 {
		return 0, false
	}
	v := uint16(p.b[p.i])<<8 | uint16(p.b[p.i+1])
	p.i += 2
	return v, true
}

// vector reads a length-prefixed vector whose length field is lenBytes wide.
func (p *parser) vector(lenBytes int) ([]byte, bool) {
	if p.remaining() < lenBytes {
		return nil, false
	}
	n := 0
	for range lenBytes {
		n = n<<8 | int(p.b[p.i])
		p.i++
	}
	if p.remaining() < n {
		return nil, false
	}
	v := p.b[p.i : p.i+n]
	p.i += n
	return v, true
}

func (p *parser) skipVector(lenBytes int) bool {
	_, ok := p.vector(lenBytes)
	return ok
}
