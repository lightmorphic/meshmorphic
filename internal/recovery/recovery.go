// Package recovery encodes a peer's identity as a written-down recovery key.
//
// This exists because of the single unrecoverable failure in MeshMorphic's
// design. A site's address is derived from its private key, and nobody else
// holds a copy — there is no account, no server-side backup, and no support
// desk with a reset button. That is precisely why the system is safe from
// being taken over, and it is also why a dead hard disk would otherwise mean
// the address is gone for good.
//
// So the key is made writable on paper. Twelve groups of five characters,
// with a checksum, in an alphabet chosen so that nothing in it can be
// misread: no 0 against O, no 1 against l, no 2 against Z.
//
// The threat model is worth being blunt about. Anyone who reads this key can
// become that site. It is equivalent to the private key, because it is the
// private key. The panel shows it once, tells the user to write it on paper,
// and does not email it, upload it, or store it anywhere it was not already.
package recovery

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
)

// Prefix marks a MeshMorphic recovery key and its version.
const Prefix = "MM1"

// alphabet is the same z-base32 alphabet used for peer IDs: no 0, 1, l or v,
// so a key read off paper cannot be transcribed into a different valid key.
const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// checksumDomain separates the checksum from every other hash in the protocol.
const checksumDomain = "meshmorphic-recovery-v1"

const (
	seedLen     = ed25519.SeedSize // 32
	checksumLen = 2                // 16 bits: enough to catch transcription slips
	groupSize   = 5
)

var (
	// ErrMalformed means the text is not a recovery key at all.
	ErrMalformed = errors.New("recovery: this does not look like a recovery key")
	// ErrChecksum means the key was mistyped. Distinguishing this from a
	// merely wrong key lets the panel say "check what you typed" rather than
	// "wrong key", which is the difference between a fixable moment and a
	// frightening one.
	ErrChecksum = errors.New("recovery: the recovery key has a typo in it")
)

// Encode renders an identity as a recovery key.
func Encode(id *identity.Identity) (string, error) {
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("recovery: identity has no usable private key")
	}
	seed := id.PrivateKey.Seed()
	payload := make([]byte, 0, seedLen+checksumLen)
	payload = append(payload, seed...)
	payload = append(payload, checksum(seed)...)

	body := encodeBase32(payload)
	var groups []string
	for i := 0; i < len(body); i += groupSize {
		end := min(i+groupSize, len(body))
		groups = append(groups, strings.ToUpper(body[i:end]))
	}
	return Prefix + "-" + strings.Join(groups, "-"), nil
}

// Decode parses a recovery key back into an identity.
//
// Input is normalised hard before parsing: case is folded, and dashes, spaces
// and tabs are dropped. Someone reading a key off paper into a phone should
// not be defeated by having typed a space in a different place.
func Decode(s string) (*identity.Identity, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n', '\r', '_':
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(s)))

	cleaned = strings.TrimPrefix(cleaned, strings.ToLower(Prefix))
	if cleaned == "" {
		return nil, ErrMalformed
	}

	payload, err := decodeBase32(cleaned)
	if err != nil {
		return nil, err
	}
	if len(payload) < seedLen+checksumLen {
		return nil, ErrMalformed
	}
	// Base32 decoding can yield a trailing partial byte; the payload is a
	// fixed length, so anything past it is padding and is ignored.
	payload = payload[:seedLen+checksumLen]

	seed := payload[:seedLen]
	want := checksum(seed)
	// Constant time is not strictly required — an attacker holding the key
	// already has everything — but a checksum compare is the kind of thing
	// that gets copied into a place where it does matter.
	if subtle.ConstantTimeCompare(payload[seedLen:], want) != 1 {
		return nil, ErrChecksum
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return &identity.Identity{
		PrivateKey: priv,
		PublicKey:  priv.Public().(ed25519.PublicKey),
	}, nil
}

// checksum returns the bytes appended to catch transcription errors.
func checksum(seed []byte) []byte {
	h := sha256.New()
	h.Write([]byte(checksumDomain))
	h.Write([]byte{0})
	h.Write(seed)
	return h.Sum(nil)[:checksumLen]
}

// encodeBase32 encodes bytes in the recovery alphabet, without padding.
func encodeBase32(b []byte) string {
	var sb strings.Builder
	var buf, bits uint
	for _, c := range b {
		buf = buf<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alphabet[(buf>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(buf<<(5-bits))&31])
	}
	return sb.String()
}

// decodeBase32 reverses encodeBase32.
func decodeBase32(s string) ([]byte, error) {
	var out []byte
	var buf, bits uint
	for _, r := range s {
		i := strings.IndexRune(alphabet, r)
		if i < 0 {
			return nil, fmt.Errorf("%w: %q is not a character used in recovery keys", ErrMalformed, string(r))
		}
		buf = buf<<5 | uint(i)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}
