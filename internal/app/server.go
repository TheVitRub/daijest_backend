package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	store Store
	cfg   Config
}

func NewServer(store Store, cfg Config) *Server {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	return &Server{store: store, cfg: cfg}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/auth/register", s.handleRegister)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/digest-types", s.handleDigestTypes)
	mux.HandleFunc("/api/digests", s.handleDigests)
	mux.HandleFunc("/api/digests/", s.handleDigestByID)
	mux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if email == "" || len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "email and password with at least 8 characters are required")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	user, err := s.store.CreateUser(r.Context(), email, strings.TrimSpace(req.Name), string(hash))
	if err != nil {
		if errors.Is(err, ErrConflict) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	token, err := s.createSession(r, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusCreated, authResponse{Token: token, User: publicUser(user)})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	var user User
	var err error

	if req.Code != "" {
		// Code-based login for managed users.
		user, err = s.store.FindUserByCode(r.Context(), strings.TrimSpace(req.Code))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid access code")
			return
		}
	} else {
		// Email + password login.
		user, err = s.store.FindUserByEmail(r.Context(), normalizeEmail(req.Email))
		if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
	}

	token, err := s.createSession(r, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusOK, authResponse{Token: token, User: publicUser(user)})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]User{"user": publicUser(user)})
}

// handleDigestTypes returns the list of available digest types.
func (s *Server) handleDigestTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"digestTypes": AllDigestTypes})
}

// handleAdminUsers manages admin-only user creation and listing.
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	_ = admin

	switch r.Method {
	case http.MethodGet:
		users, err := s.store.ListUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list users")
			return
		}
		writeJSON(w, http.StatusOK, adminUsersResponse{Users: users})

	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		code, err := generateAccessCode()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not generate access code")
			return
		}
		user, err := s.store.CreateManagedUser(r.Context(), name, code)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create user")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]User{"user": user})

	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleDigests(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		digests, err := s.store.ListDigests(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list digests")
			return
		}
		writeJSON(w, http.StatusOK, digestsResponse{Digests: digests})
	case http.MethodPost:
		var req struct {
			Title      string          `json:"title"`
			DigestType string          `json:"digestType"`
			State      json.RawMessage `json:"state"`
			Action     string          `json:"action"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		state, ok := normalizeState(w, req.State)
		if !ok {
			return
		}
		digest, _, err := s.store.CreateDigest(r.Context(), user.ID, cleanTitle(req.Title), resolveDigestType(req.DigestType), state, defaultAction(req.Action, "created"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create digest")
			return
		}
		writeJSON(w, http.StatusCreated, digestResponse{Digest: digest})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleDigestByID(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/digests/"), "/")
	if len(parts) == 1 && parts[0] == "import" {
		s.handleImport(w, r, user)
		return
	}
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "digest not found")
		return
	}
	digestID := parts[0]

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			digest, err := s.store.GetDigest(r.Context(), user.ID, digestID)
			if err != nil {
				writeStoreError(w, err, "digest not found")
				return
			}
			writeJSON(w, http.StatusOK, digestResponse{Digest: digest})
		case http.MethodDelete:
			if err := s.store.DeleteDigest(r.Context(), user.ID, digestID); err != nil {
				writeStoreError(w, err, "digest not found")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w)
		}
		return
	}

	switch parts[1] {
	case "autosave":
		s.handleAutosave(w, r, user, digestID)
	case "revisions":
		if len(parts) == 2 {
			s.handleRevisions(w, r, user, digestID)
			return
		}
		if len(parts) == 3 {
			s.handleRevisionByID(w, r, user, digestID, parts[2])
			return
		}
		writeError(w, http.StatusNotFound, "route not found")
	case "rollback":
		s.handleRollback(w, r, user, digestID)
	case "export":
		s.handleExport(w, r, user, digestID)
	default:
		writeError(w, http.StatusNotFound, "route not found")
	}
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		Title      string          `json:"title"`
		DigestType string          `json:"digestType"`
		State      json.RawMessage `json:"state"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	state, ok := normalizeState(w, req.State)
	if !ok {
		return
	}
	digest, _, err := s.store.CreateDigest(r.Context(), user.ID, cleanTitle(req.Title), resolveDigestType(req.DigestType), state, "imported")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not import digest")
		return
	}
	writeJSON(w, http.StatusCreated, digestResponse{Digest: digest})
}

func (s *Server) handleAutosave(w http.ResponseWriter, r *http.Request, user User, digestID string) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	var req struct {
		Title      string          `json:"title"`
		DigestType string          `json:"digestType"`
		State      json.RawMessage `json:"state"`
		Action     string          `json:"action"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	state, ok := normalizeState(w, req.State)
	if !ok {
		return
	}
	// Pass empty DigestType to preserve the current value when not provided.
	_, revision, err := s.store.AutosaveDigest(r.Context(), user.ID, digestID, cleanTitle(req.Title), DigestType(req.DigestType), state, defaultAction(req.Action, "autosaved"))
	if err != nil {
		writeStoreError(w, err, "digest not found")
		return
	}
	writeJSON(w, http.StatusOK, revisionResponse{Revision: revision})
}

func (s *Server) handleRevisions(w http.ResponseWriter, r *http.Request, user User, digestID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	revisions, err := s.store.ListRevisions(r.Context(), user.ID, digestID)
	if err != nil {
		writeStoreError(w, err, "digest not found")
		return
	}
	writeJSON(w, http.StatusOK, revisionsResponse{Revisions: revisions})
}

func (s *Server) handleRevisionByID(w http.ResponseWriter, r *http.Request, user User, digestID, revisionID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	revision, err := s.store.GetRevision(r.Context(), user.ID, digestID, revisionID)
	if err != nil {
		writeStoreError(w, err, "revision not found")
		return
	}
	writeJSON(w, http.StatusOK, revisionResponse{Revision: revision})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, user User, digestID string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		RevisionID string `json:"revisionId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	revision, err := s.store.GetRevision(r.Context(), user.ID, digestID, req.RevisionID)
	if err != nil {
		writeStoreError(w, err, "revision not found")
		return
	}
	current, err := s.store.GetDigest(r.Context(), user.ID, digestID)
	if err != nil {
		writeStoreError(w, err, "digest not found")
		return
	}
	digest, _, err := s.store.AutosaveDigest(r.Context(), user.ID, digestID, current.Title, current.DigestType, revision.State, "rollback to version "+itoa(revision.Version))
	if err != nil {
		writeStoreError(w, err, "digest not found")
		return
	}
	writeJSON(w, http.StatusOK, digestResponse{Digest: digest})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, user User, digestID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	digest, err := s.store.GetDigest(r.Context(), user.ID, digestID)
	if err != nil {
		writeStoreError(w, err, "digest not found")
		return
	}
	writeJSON(w, http.StatusOK, exportResponse{SchemaVersion: 1, State: digest.State})
}

func (s *Server) createSession(r *http.Request, userID string) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	err = s.store.CreateSession(r.Context(), userID, tokenHash(token), time.Now().Add(s.cfg.SessionTTL))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "authorization required")
		return User{}, false
	}
	user, err := s.store.FindUserBySession(r.Context(), tokenHash(strings.TrimPrefix(header, "Bearer ")), time.Now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authorization required")
		return User{}, false
	}
	return user, true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return User{}, false
	}
	if !user.IsAdmin {
		writeError(w, http.StatusForbidden, "admin access required")
		return User{}, false
	}
	return user, true
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func writeStoreError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, fallback)
		return
	}
	writeError(w, http.StatusInternalServerError, "storage error")
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func cleanTitle(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return "Untitled digest"
	}
	return title
}

func defaultAction(action, fallback string) string {
	action = strings.TrimSpace(action)
	if action == "" {
		return fallback
	}
	return action
}

func normalizeState(w http.ResponseWriter, raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage(`{}`)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		writeError(w, http.StatusBadRequest, "state must be valid json")
		return nil, false
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "state must be valid json")
		return nil, false
	}
	return normalized, true
}

// resolveDigestType returns the provided type if valid, otherwise defaults to analytical.
func resolveDigestType(raw string) DigestType {
	t := DigestType(raw)
	if t.Valid() {
		return t
	}
	return DigestTypeAnalytical
}

func publicUser(user User) User {
	user.PasswordHash = ""
	return user
}

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// generateAccessCode produces a cryptographically random 8-digit numeric code.
func generateAccessCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	v := value
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
