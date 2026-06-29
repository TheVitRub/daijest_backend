package app

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Per-image upload ceiling (defense in depth; nginx also caps the body). The
// frontend downscales before upload, so real images are well under this.
const maxMediaUpload = 20 << 20 // 20 MiB

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// allowedMediaTypes whitelists image formats we accept and serve. SVG is
// deliberately excluded: serving user SVG same-origin would allow script
// execution (XSS).
var allowedMediaTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/webp": true,
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// mediaPath maps an id to its on-disk location, sharded by the first two byte
// pairs to avoid one giant directory: <dir>/3f/2e/<id>.
func (s *Server) mediaPath(id string) string {
	return filepath.Join(s.cfg.MediaDir, id[0:2], id[2:4], id)
}

// handleMediaUpload accepts one image (multipart field "file") from an
// authenticated user, streams it to disk, and stores its metadata.
func (s *Server) handleMediaUpload(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if s.cfg.MediaDir == "" {
		writeError(w, http.StatusInternalServerError, "media storage not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMediaUpload)
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "file too large or invalid form")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file field is required")
		return
	}
	defer file.Close()

	// Sniff the real type from the first bytes — never trust the client header.
	head := make([]byte, 512)
	n, err := io.ReadFull(file, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		writeError(w, http.StatusBadRequest, "could not read upload")
		return
	}
	head = head[:n]
	contentType := http.DetectContentType(head)
	if !allowedMediaTypes[contentType] {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported image type")
		return
	}

	id, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not allocate id")
		return
	}
	dst := s.mediaPath(id)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare storage")
		return
	}
	out, err := os.Create(dst)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not write file")
		return
	}

	hasher := sha256.New()
	src := io.TeeReader(io.MultiReader(bytes.NewReader(head), file), hasher)
	size, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dst)
		writeError(w, http.StatusInternalServerError, "could not store file")
		return
	}

	meta := MediaMeta{
		ID:          id,
		UserID:      user.ID,
		ContentType: contentType,
		Size:        size,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
	}
	if err := s.store.SaveMedia(r.Context(), meta); err != nil {
		_ = os.Remove(dst) // don't leave an orphan file with no DB record
		writeError(w, http.StatusInternalServerError, "could not save media")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// handleMediaDownload streams an image by id. Capability-style: the unguessable
// UUID is the authorization, so <img> can load it without a token.
func (s *Server) handleMediaDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/media/"), "/")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "media not found")
		return
	}
	meta, err := s.store.GetMedia(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "media not found")
		return
	}
	f, err := os.Open(s.mediaPath(id))
	if err != nil {
		writeError(w, http.StatusNotFound, "media not found")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read media")
		return
	}
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	// Empty name => ServeContent keeps our Content-Type and adds Range + caching.
	http.ServeContent(w, r, "", info.ModTime(), f)
}
