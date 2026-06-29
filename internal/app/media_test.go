package app

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// pngBytes returns data whose first bytes are a PNG signature so
// http.DetectContentType classifies it as image/png.
func pngBytes() []byte {
	return append([]byte("\x89PNG\r\n\x1a\n"), []byte("fake-png-payload-for-tests")...)
}

func uploadMedia(t *testing.T, server *Server, token, filename string, data []byte, wantStatus int) string {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/media", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	server.Routes().ServeHTTP(res, req)
	if res.Code != wantStatus {
		t.Fatalf("POST /api/media status = %d, body = %s", res.Code, res.Body.String())
	}
	if wantStatus != http.StatusCreated {
		return ""
	}
	var out map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode upload response: %v; body = %s", err, res.Body.String())
	}
	if out["id"] == "" {
		t.Fatal("upload returned empty id")
	}
	return out["id"]
}

func TestMediaUploadDownloadRoundTrip(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour, MediaDir: t.TempDir()})
	auth := setupAdmin(t, server, "11111111")

	data := pngBytes()
	id := uploadMedia(t, server, auth.Token, "photo.png", data, http.StatusCreated)

	req := httptest.NewRequest(http.MethodGet, "/api/media/"+id, nil)
	res := httptest.NewRecorder()
	server.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET media status = %d, body = %s", res.Code, res.Body.String())
	}
	if ct := res.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content-type = %q, want image/png", ct)
	}
	if res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
	if !bytes.Equal(res.Body.Bytes(), data) {
		t.Fatal("downloaded bytes do not match uploaded bytes")
	}
}

func TestMediaUploadRequiresAuth(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour, MediaDir: t.TempDir()})
	uploadMedia(t, server, "", "photo.png", pngBytes(), http.StatusUnauthorized)
}

func TestMediaUploadRejectsNonImage(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour, MediaDir: t.TempDir()})
	auth := setupAdmin(t, server, "11111111")
	uploadMedia(t, server, auth.Token, "note.txt", []byte("just some plain text, not an image"), http.StatusUnsupportedMediaType)
}

func TestMediaDownloadRejectsBadID(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour, MediaDir: t.TempDir()})

	// Non-UUID / traversal-shaped ids must never serve a file. Some inputs are
	// rejected by our uuid check (404); dot-segment paths are cleaned away by the
	// router (301 redirect) before reaching the handler. Either way: never 200.
	for _, bad := range []string{"not-a-uuid", "deadbeef", "../../etc/passwd", "00000000-0000-0000-0000-000000000000"} {
		req := httptest.NewRequest(http.MethodGet, "/api/media/"+bad, nil)
		res := httptest.NewRecorder()
		server.Routes().ServeHTTP(res, req)
		if res.Code == http.StatusOK {
			t.Fatalf("GET /api/media/%s returned 200 — must not serve", bad)
		}
	}
}
