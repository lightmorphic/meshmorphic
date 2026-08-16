// Package names produces a spoken nickname for a peer, derived from its
// public key.
//
// This is cosmetic and nothing else. It exists so that the installer can say
// "your site is brave-otter-canyon" to somebody who will never memorise a
// fingerprint, and so that logs are readable. It is never used to route
// traffic and never used to authorise anything.
//
// Two different keys can produce the same nickname — with roughly 660,000
// combinations they will, eventually. That is harmless precisely because
// nothing depends on it. Routing uses identity.HostLabel, which is derived
// from the same key with ninety-six bits behind it.
//
// The derivation is deterministic, so a peer's nickname is a property of its
// key rather than something assigned to it. Nobody hands these out, which
// means there is no register of them anywhere and nothing to take.
//
// The words are chosen to be short, unambiguous when spoken, free of
// homophones, and incapable of combining into anything a person would be
// embarrassed to say out loud.
package names

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
)

var adjectives = []string{
	"amber", "ancient", "arctic", "autumn", "azure", "brave", "brass", "bright",
	"bronze", "calm", "candid", "cedar", "clear", "clever", "cobalt", "copper",
	"coral", "cosmic", "crimson", "crisp", "curious", "dawn", "deep", "dusty",
	"eager", "early", "east", "ember", "fair", "fern", "fleet", "fluent",
	"frosty", "gentle", "gilded", "glad", "golden", "granite", "green", "hardy",
	"hazel", "hidden", "humble", "indigo", "ivory", "jade", "keen", "kind",
	"lively", "lucid", "lunar", "maple", "marble", "merry", "mild", "misty",
	"noble", "north", "olive", "opal", "patient", "pearl", "plain", "polar",
	"prime", "proud", "quiet", "rapid", "ready", "rustic", "sable", "sage",
	"sandy", "scarlet", "silent", "silver", "slate", "smooth", "solar", "solid",
	"south", "spry", "steady", "still", "stone", "sunny", "swift", "teal",
	"tidy", "topaz", "true", "twilight", "umber", "upland", "velvet", "violet",
	"warm", "west", "willow", "winter", "wise", "zesty",
}

var animals = []string{
	"adder", "badger", "beetle", "bison", "bittern", "cormorant", "crane", "cricket",
	"curlew", "dipper", "dormouse", "dunlin", "eagle", "egret", "falcon", "ferret",
	"finch", "gannet", "godwit", "goshawk", "grebe", "hare", "harrier", "heron",
	"hornet", "ibis", "jackdaw", "kestrel", "kingfisher", "kite", "lapwing", "linnet",
	"lynx", "magpie", "marten", "merlin", "mole", "moth", "newt", "nuthatch",
	"osprey", "otter", "owl", "oyster", "petrel", "pipit", "plover", "pochard",
	"puffin", "quail", "raven", "redwing", "ringtail", "robin", "rook", "salmon",
	"sandpiper", "seal", "shrew", "siskin", "skylark", "snipe", "sparrow", "stoat",
	"stonechat", "swallow", "swift", "teal", "tern", "thrush", "tortoise", "trout",
	"turnstone", "vole", "wagtail", "warbler", "weasel", "wheatear", "whimbrel", "wigeon",
	"woodcock", "wren",
}

var places = []string{
	"anchor", "arbour", "arch", "bay", "beacon", "bend", "bluff", "bridge",
	"brook", "cairn", "canyon", "cavern", "channel", "cliff", "combe", "copse",
	"cove", "crag", "creek", "crescent", "croft", "dale", "delta", "dell",
	"dune", "estuary", "fell", "fjord", "ford", "forest", "fountain", "garden",
	"gate", "glade", "glen", "grove", "harbour", "haven", "headland", "hollow",
	"island", "isle", "knoll", "lagoon", "lake", "ledge", "lighthouse", "meadow",
	"mere", "mill", "moor", "mount", "narrows", "oasis", "orchard", "outpost",
	"paddock", "pass", "pier", "pines", "plateau", "pool", "prairie", "quarry",
	"quay", "rapids", "reach", "reef", "ridge", "rise", "river", "sands",
	"shore", "spring", "steppe", "strand", "summit", "terrace", "thicket", "trail",
	"tundra", "vale", "valley", "verge", "wharf", "willows",
}

func init() {
	// A stray space in a wordlist becomes an invalid hostname months later and
	// is miserable to trace. Fail at start-up, loudly, instead.
	for _, list := range [][]string{adjectives, animals, places} {
		for _, w := range list {
			if strings.TrimSpace(w) != w || w == "" || strings.ContainsAny(w, " \t.") {
				panic(fmt.Sprintf("names: wordlist entry %q is not a clean label", w))
			}
		}
	}
}

// nicknameDomain separates this derivation from every other use of the key.
const nicknameDomain = "meshmorphic-nickname-v1"

// Space is the number of distinct nicknames available.
func Space() int { return len(adjectives) * len(animals) * len(places) }

// Nickname returns the three-word spoken name for a public key, such as
// "brave-otter-canyon".
//
// Each word is chosen by a separate two-byte window of the hash. The slight
// modulo bias that leaves is irrelevant here: this picks a label to say out
// loud, not a secret, and nothing checks it.
func Nickname(pub ed25519.PublicKey) string {
	h := sha256.New()
	h.Write([]byte(nicknameDomain))
	h.Write([]byte{0})
	h.Write(pub)
	sum := h.Sum(nil)

	word := func(list []string, offset int) string {
		v := int(sum[offset])<<8 | int(sum[offset+1])
		return list[v%len(list)]
	}
	return word(adjectives, 0) + "-" + word(animals, 2) + "-" + word(places, 4)
}

// Valid reports whether s has the shape this package produces. Used when
// echoing a nickname back into human-facing output, so a malformed value from
// a remote peer cannot smuggle anything into a terminal or a web page.
func Valid(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}
