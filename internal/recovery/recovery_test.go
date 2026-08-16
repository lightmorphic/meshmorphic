package recovery

import (
	"errors"
	"strings"
	"testing"

	"github.com/FOSSCharlie/meshmorphic/internal/identity"
)

func TestRoundTrip(t *testing.T) {
	original, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	restored, err := Decode(key)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if restored.ID() != original.ID() {
		t.Fatalf("restored a different identity: %s != %s", original.ID(), restored.ID())
	}
	if !restored.PrivateKey.Equal(original.PrivateKey) {
		t.Fatal("the restored private key differs from the original")
	}
}

// Somebody reading a key off a piece of paper will get the spacing and the
// case wrong. If that failed, the backup would be worthless in exactly the
// situation it exists for.
func TestDecodeToleratesHumanTranscription(t *testing.T) {
	id, _ := identity.Generate()
	key, err := Encode(id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	variants := map[string]string{
		"as printed":               key,
		"lower case":               strings.ToLower(key),
		"no dashes":                strings.ReplaceAll(key, "-", ""),
		"spaces instead":           strings.ReplaceAll(key, "-", " "),
		"surrounded by whitespace": "\n  " + key + "  \n",
		"underscores":              strings.ReplaceAll(key, "-", "_"),
	}
	for name, variant := range variants {
		restored, err := Decode(variant)
		if err != nil {
			t.Fatalf("%s: Decode: %v", name, err)
		}
		if restored.ID() != id.ID() {
			t.Fatalf("%s: restored the wrong identity", name)
		}
	}
}

// A single mistyped character must be reported as a typo rather than silently
// producing a different, valid-looking identity. Without the checksum somebody
// would restore, see a working agent, and only discover much later that it had
// the wrong address.
func TestDecodeCatchesTypos(t *testing.T) {
	id, _ := identity.Generate()
	key, _ := Encode(id)

	body := strings.ReplaceAll(strings.TrimPrefix(key, Prefix+"-"), "-", "")
	caught := 0
	for i := range body {
		// Swap one character for a different one from the alphabet.
		replacement := byte('y')
		if body[i] == 'y' {
			replacement = 'n'
		}
		mutated := Prefix + "-" + body[:i] + string(replacement) + body[i+1:]

		restored, err := Decode(mutated)
		if err != nil {
			if errors.Is(err, ErrChecksum) || errors.Is(err, ErrMalformed) {
				caught++
			}
			continue
		}
		if restored.ID() == id.ID() {
			// A changed character that decodes to the same identity means it
			// landed in the padding, which is harmless.
			caught++
		}
	}
	// The checksum is sixteen bits, so a stray survivor is statistically
	// expected; a systemic failure is not.
	if ratio := float64(caught) / float64(len(body)); ratio < 0.95 {
		t.Fatalf("only %.0f%% of single-character typos were caught", ratio*100)
	}
}

func TestDecodeRejectsRubbish(t *testing.T) {
	for _, bad := range []string{
		"",
		"MM1",
		"hello world",
		"MM1-00000-00000", // 0 is not in the alphabet
		"MM1-yyyyy",       // far too short
	} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("Decode accepted %q", bad)
		}
	}
}

// The printed key must not contain characters that are easily confused when
// read aloud or copied by hand, because that is the entire reason for using
// this alphabet rather than standard base32.
func TestEncodedKeyAvoidsAmbiguousCharacters(t *testing.T) {
	id, _ := identity.Generate()
	key, _ := Encode(id)

	body := strings.ToLower(strings.TrimPrefix(key, Prefix))
	for _, ambiguous := range []string{"0", "l", "v", "2"} {
		if strings.Contains(body, ambiguous) {
			t.Fatalf("recovery key %q contains the ambiguous character %q", key, ambiguous)
		}
	}
}
