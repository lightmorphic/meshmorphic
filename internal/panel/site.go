package panel

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Limits on an uploaded website.
//
// Every one of these exists because the input is a file chosen by a human who
// may have chosen the wrong one, or by an attacker who has got past device
// pairing. A zip archive can claim to be small and expand without bound, so
// the decompressed total is capped as well as the upload itself.
const (
	maxUploadBytes  = 512 << 20 // 512 MiB compressed
	maxExtractBytes = 2 << 30   // 2 GiB decompressed
	maxFiles        = 20000
)

// SiteFile describes one file of the published website.
type SiteFile struct {
	Name string
	Size int64
}

// handleSite renders the website page.
func (s *Server) handleSite(w http.ResponseWriter, r *http.Request) {
	files, err := listSite(s.cfg.SiteDir)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hasIndex := false
	for _, f := range files {
		if f.Name == "index.html" {
			hasIndex = true
			break
		}
	}
	s.render(w, r, "site.html", map[string]any{
		"Title":    "Your website files",
		"Files":    files,
		"HasIndex": hasIndex,
		"Count":    len(files),
		"Error":    r.URL.Query().Get("error"),
	})
}

// handleUpload replaces the website with an uploaded zip archive.
//
// The replacement is all-or-nothing: the archive is expanded into a fresh
// directory and only swapped into place once it has fully succeeded. A failed
// or half-finished upload therefore leaves the running site untouched, rather
// than leaving somebody's website half-deleted.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.flashBack(w, r, "/site", "That upload was too large or could not be read.")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	file, header, err := r.FormFile("archive")
	if err != nil {
		s.flashBack(w, r, "/site", "Please choose a .zip file containing your website.")
		return
	}
	defer func() { _ = file.Close() }()

	if !strings.EqualFold(filepath.Ext(header.Filename), ".zip") {
		s.flashBack(w, r, "/site", "That file is not a .zip archive.")
		return
	}

	// A zip reader needs to seek, so the upload is spooled to a temporary file
	// next to the site directory rather than held in memory.
	tmpFile, err := os.CreateTemp(filepath.Dir(s.cfg.SiteDir), ".mm-upload-*.zip")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	size, err := io.Copy(tmpFile, file)
	if err != nil {
		s.flashBack(w, r, "/site", "The upload did not finish.")
		return
	}

	staging, err := os.MkdirTemp(filepath.Dir(s.cfg.SiteDir), ".mm-staging-*")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer func() { _ = os.RemoveAll(staging) }()

	zr, err := zip.NewReader(tmpFile, size)
	if err != nil {
		s.flashBack(w, r, "/site", "That file could not be opened as a zip archive.")
		return
	}
	if err := extractZip(zr, staging); err != nil {
		s.flashBack(w, r, "/site", err.Error())
		return
	}

	// A site whose files sit inside a single folder is what you get from
	// "compress this folder" on every desktop, so it is unwrapped rather than
	// rejected.
	if err := unwrapSingleDir(staging); err != nil {
		s.serverError(w, r, err)
		return
	}

	if err := swapDir(staging, s.cfg.SiteDir); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("website replaced", "files", header.Filename, "bytes", size)
	http.Redirect(w, r, "/site", http.StatusSeeOther)
}

// extractZip expands an archive into dest, refusing anything that tries to
// write outside it.
func extractZip(zr *zip.Reader, dest string) error {
	if len(zr.File) > maxFiles {
		return fmt.Errorf("that archive contains more than %d files", maxFiles)
	}
	var written int64

	for _, f := range zr.File {
		// Path traversal defence. An archive entry named "../../etc/cron.d/x"
		// is the classic way to turn an upload feature into remote code
		// execution, so the cleaned path must stay inside the destination.
		name := path.Clean("/" + strings.ReplaceAll(f.Name, `\`, "/"))
		name = strings.TrimPrefix(name, "/")
		if name == "" || name == "." {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return errors.New("that archive contains a file path that points outside the website folder")
		}

		info := f.FileInfo()
		if info.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("could not create a folder from the archive: %w", err)
			}
			continue
		}
		// Symbolic links are refused outright. A link is the other way an
		// archive escapes its directory, and a static website has no need
		// of one.
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("that archive contains a symbolic link, which is not allowed")
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("could not create a folder from the archive: %w", err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("could not read a file from the archive: %w", err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("could not write a file from the archive: %w", err)
		}
		// Copy through a limit rather than trusting the archive's declared
		// size, which is what makes a decompression bomb harmless here.
		n, err := io.Copy(out, io.LimitReader(rc, maxExtractBytes-written))
		_ = out.Close()
		_ = rc.Close()
		if err != nil {
			return fmt.Errorf("could not write a file from the archive: %w", err)
		}
		written += n
		if written >= maxExtractBytes {
			return errors.New("that archive expands to more than this system will accept")
		}
	}
	return nil
}

// unwrapSingleDir flattens a staging directory that contains exactly one
// folder and nothing else.
func unwrapSingleDir(staging string) error {
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return nil
	}
	inner := filepath.Join(staging, entries[0].Name())
	innerEntries, err := os.ReadDir(inner)
	if err != nil {
		return err
	}
	for _, e := range innerEntries {
		if err := os.Rename(filepath.Join(inner, e.Name()), filepath.Join(staging, e.Name())); err != nil {
			return err
		}
	}
	return os.Remove(inner)
}

// swapDir replaces dest with staging, keeping the previous contents until the
// swap has succeeded.
func swapDir(staging, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	old := dest + ".previous"
	_ = os.RemoveAll(old)

	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return fmt.Errorf("could not move the previous website aside: %w", err)
		}
	}
	if err := os.Rename(staging, dest); err != nil {
		// Put the previous site back rather than leaving the machine with no
		// website at all.
		_ = os.Rename(old, dest)
		return fmt.Errorf("could not put the new website in place: %w", err)
	}
	// Recreate the staging path so the deferred cleanup in the caller has
	// something harmless to remove.
	_ = os.MkdirAll(staging, 0o755)
	return os.RemoveAll(old)
}

// listSite enumerates the published files.
func listSite(dir string) ([]SiteFile, error) {
	var out []SiteFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, SiteFile{Name: filepath.ToSlash(rel), Size: info.Size()})
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// fsSub is fs.Sub, wrapped so the caller gets a useful error message.
func fsSub(fsys fs.FS, dir string) (fs.FS, error) {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("panel: embedded assets missing %s: %w", dir, err)
	}
	return sub, nil
}
