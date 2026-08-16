package panel

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A page on the public internet must not be able to reach a panel bound to a
// private address by pointing its own hostname at that address. Pinning the
// acceptable Host values is what breaks that attack, so these cases are the
// difference between a private control panel and a public one.
func TestIsLocalHostHeader(t *testing.T) {
	allowed := []string{
		"localhost", "localhost:8800",
		"127.0.0.1", "127.0.0.1:8800",
		"192.168.1.50:8800", "10.0.0.4:8800", "172.16.3.9:8800",
		"meshmorphic.local:8800", "raspberrypi.local",
		"[::1]:8800",
		"169.254.10.10:8800",
	}
	for _, host := range allowed {
		if !isLocalHostHeader(host) {
			t.Errorf("isLocalHostHeader(%q) = false, want true", host)
		}
	}

	refused := []string{
		"", "example.com", "example.com:8800",
		"attacker.test", "panel.attacker.test:8800",
		"8.8.8.8:8800", "203.0.113.10",
		// A public address dressed up to look local.
		"192.168.1.50.attacker.test:8800",
		"localhost.attacker.test",
	}
	for _, host := range refused {
		if isLocalHostHeader(host) {
			t.Errorf("isLocalHostHeader(%q) = true, want false", host)
		}
	}
}

// Anything that changes state must prove it came from the panel's own pages.
func TestCheckSameOrigin(t *testing.T) {
	newReq := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest("POST", "http://192.168.1.50:8800/domains/add", nil)
		r.Host = "192.168.1.50:8800"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}

	ok := []map[string]string{
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "none"},
		{"Origin": "http://192.168.1.50:8800"},
		// Case in the host should not matter.
		{"Origin": "http://192.168.1.50:8800", "Sec-Fetch-Site": ""},
	}
	for _, headers := range ok {
		if err := checkSameOrigin(newReq(headers)); err != nil {
			t.Errorf("checkSameOrigin(%v) = %v, want nil", headers, err)
		}
	}

	bad := []map[string]string{
		{}, // neither header: refused rather than assumed safe
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "http://attacker.test"},
		{"Origin": "http://192.168.1.51:8800"},  // a different machine on the same network
		{"Origin": "https://192.168.1.50:8800"}, // scheme differs, so Host differs in practice
	}
	for _, headers := range bad {
		if err := checkSameOrigin(newReq(headers)); err == nil {
			t.Errorf("checkSameOrigin(%v) = nil, want an error", headers)
		}
	}
}

// buildZip makes an in-memory archive with the given entries.
func buildZip(t *testing.T, entries map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	return zr
}

func TestExtractZipNormalCase(t *testing.T) {
	dest := t.TempDir()
	zr := buildZip(t, map[string]string{
		"index.html":    "<h1>hello</h1>",
		"css/style.css": "body{}",
		"img/logo.svg":  "<svg/>",
	})
	if err := extractZip(zr, dest); err != nil {
		t.Fatalf("extractZip: %v", err)
	}
	for _, want := range []string{"index.html", "css/style.css", "img/logo.svg"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(want))); err != nil {
			t.Errorf("expected %s to be extracted: %v", want, err)
		}
	}
}

// An archive entry that climbs out of the destination directory is the classic
// route from "upload a website" to "write anywhere on the machine". It must be
// refused rather than cleaned up and accepted.
func TestExtractZipRefusesPathTraversal(t *testing.T) {
	cases := map[string]string{
		"parent directory":        "../escaped.txt",
		"deep parent":             "../../../../etc/cron.d/payload",
		"absolute path":           "/etc/cron.d/payload",
		"windows separators":      `..\..\escaped.txt`,
		"traversal in the middle": "assets/../../escaped.txt",
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "site")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}

			zr := buildZip(t, map[string]string{entry: "payload"})
			err := extractZip(zr, dest)

			// Either the entry is refused outright, or it is confined. What
			// must never happen is a file appearing outside the destination.
			escaped := filepath.Join(parent, "escaped.txt")
			if _, statErr := os.Stat(escaped); statErr == nil {
				t.Fatalf("entry %q escaped the destination directory (extractZip returned %v)", entry, err)
			}
			if _, statErr := os.Stat("/etc/cron.d/payload"); statErr == nil {
				t.Fatalf("entry %q wrote outside the destination entirely", entry)
			}
		})
	}
}

func TestExtractZipRefusesTooManyFiles(t *testing.T) {
	entries := make(map[string]string, maxFiles+10)
	for i := range maxFiles + 10 {
		entries[strings.Repeat("a", 1)+string(rune('a'+i%26))+"/"+itoa(i)+".txt"] = "x"
	}
	zr := buildZip(t, entries)
	if err := extractZip(zr, t.TempDir()); err == nil {
		t.Fatal("an archive with too many files was accepted")
	}
}

// unwrapSingleDir exists because every desktop's "compress this folder"
// produces exactly this shape, and rejecting it would fail most first uploads.
func TestUnwrapSingleDir(t *testing.T) {
	staging := t.TempDir()
	inner := filepath.Join(staging, "my-website")
	if err := os.MkdirAll(filepath.Join(inner, "css"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unwrapSingleDir(staging); err != nil {
		t.Fatalf("unwrapSingleDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, "index.html")); err != nil {
		t.Fatalf("index.html was not lifted to the top level: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, "css")); err != nil {
		t.Fatalf("css directory was not lifted to the top level: %v", err)
	}
}

func TestUnwrapSingleDirLeavesMultipleEntriesAlone(t *testing.T) {
	staging := t.TempDir()
	if err := os.WriteFile(filepath.Join(staging, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(staging, "css"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unwrapSingleDir(staging); err != nil {
		t.Fatalf("unwrapSingleDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, "index.html")); err != nil {
		t.Fatalf("a normal archive was disturbed: %v", err)
	}
}

// A failed swap must leave the running website intact. Somebody uploading the
// wrong file should not end up with no site at all.
func TestSwapDirReplacesAtomically(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "site")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "old.html"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	staging, err := os.MkdirTemp(parent, "staging-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "new.html"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := swapDir(staging, dest); err != nil {
		t.Fatalf("swapDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "new.html")); err != nil {
		t.Errorf("the new site is not in place: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "old.html")); err == nil {
		t.Error("the old site was left behind")
	}
	if _, err := os.Stat(dest + ".previous"); err == nil {
		t.Error("the previous-site directory was not cleaned up")
	}
}

// Device tokens must be stored hashed, so the state file is not itself a set
// of keys to the panel.
func TestDeviceTokensAreStoredHashed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	store, err := openDeviceStore(path)
	if err != nil {
		t.Fatalf("openDeviceStore: %v", err)
	}
	token, err := store.Enroll("Firefox on Linux")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("the device token was written to disk in the clear")
	}
	if !store.Verify(token) {
		t.Fatal("a freshly enrolled token did not verify")
	}
	if store.Verify(token + "x") {
		t.Fatal("a wrong token verified")
	}
	if store.Verify("") {
		t.Fatal("an empty token verified")
	}
}

func TestDeviceApprovalFlow(t *testing.T) {
	store, err := openDeviceStore(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !store.Empty() {
		t.Fatal("a fresh store should be empty")
	}
	if _, err := store.Enroll("owner"); err != nil {
		t.Fatal(err)
	}

	req, err := store.RequestAccess("Chrome on Android")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if store.Verify(req.Token) {
		t.Fatal("a device was admitted before being approved")
	}
	if err := store.Approve("000000"); err == nil {
		t.Fatal("an invalid code was accepted")
	}
	if err := store.Approve(req.Code); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !store.Verify(req.Token) {
		t.Fatal("an approved device was not admitted")
	}
	// A code must not be reusable.
	if err := store.Approve(req.Code); err == nil {
		t.Fatal("an approval code was accepted twice")
	}
}

// The pending list is rendered into a page, so it must not carry the token
// that would grant access.
func TestPendingDoesNotLeakTokens(t *testing.T) {
	store, err := openDeviceStore(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Enroll("owner"); err != nil {
		t.Fatal(err)
	}
	req, err := store.RequestAccess("Safari on Mac")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range store.Pending() {
		if p.Token != "" {
			t.Fatal("Pending() exposed a device token")
		}
		if p.Code != req.Code {
			t.Fatalf("Pending() reported code %q, want %q", p.Code, req.Code)
		}
	}
}

// itoa avoids pulling strconv in just for the file-count test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
