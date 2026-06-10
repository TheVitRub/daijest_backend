package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthDigestAutosaveRollbackAndExport(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{
		SessionTTL: time.Hour,
	})

	user := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/register", "", map[string]any{
		"email":    "editor@example.com",
		"name":     "Editor",
		"password": "secret-123",
	}, http.StatusCreated)
	if user.Token == "" {
		t.Fatalf("register token is empty")
	}
	if user.User.Email != "editor@example.com" {
		t.Fatalf("registered email = %q", user.User.Email)
	}

	login := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/login", "", map[string]any{
		"email":    "editor@example.com",
		"password": "secret-123",
	}, http.StatusOK)
	if login.Token == "" {
		t.Fatalf("login token is empty")
	}

	initialState := map[string]any{
		"digestCover": "data:image/png;base64,AAA",
		"letter": map[string]any{
			"title":      "Initial",
			"paragraphs": "One",
		},
		"companies": []any{},
	}
	created := postJSON[digestResponse](t, server, http.MethodPost, "/api/digests", login.Token, map[string]any{
		"title": "June digest",
		"state": initialState,
	}, http.StatusCreated)
	if created.Digest.ID == "" {
		t.Fatalf("created digest id is empty")
	}
	if created.Digest.CurrentVersion != 1 {
		t.Fatalf("created digest version = %d", created.Digest.CurrentVersion)
	}

	updatedState := map[string]any{
		"digestCover": "data:image/png;base64,BBB",
		"letter": map[string]any{
			"title":      "Updated",
			"paragraphs": "Two",
		},
		"companies": []any{},
	}
	saved := postJSON[revisionResponse](t, server, http.MethodPut, "/api/digests/"+created.Digest.ID+"/autosave", login.Token, map[string]any{
		"title":  "June digest",
		"state":  updatedState,
		"action": "typed title",
	}, http.StatusOK)
	if saved.Revision.Version != 2 {
		t.Fatalf("autosave revision version = %d", saved.Revision.Version)
	}

	loaded := getJSON[digestResponse](t, server, "/api/digests/"+created.Digest.ID, login.Token, http.StatusOK)
	if loaded.Digest.CurrentVersion != 2 {
		t.Fatalf("loaded version = %d", loaded.Digest.CurrentVersion)
	}
	if string(loaded.Digest.State) != `{"companies":[],"digestCover":"data:image/png;base64,BBB","letter":{"paragraphs":"Two","title":"Updated"}}` {
		t.Fatalf("loaded state = %s", loaded.Digest.State)
	}

	revisions := getJSON[revisionsResponse](t, server, "/api/digests/"+created.Digest.ID+"/revisions", login.Token, http.StatusOK)
	if len(revisions.Revisions) != 2 {
		t.Fatalf("revision count = %d", len(revisions.Revisions))
	}
	openedRevision := getJSON[revisionResponse](t, server, "/api/digests/"+created.Digest.ID+"/revisions/"+revisions.Revisions[0].ID, login.Token, http.StatusOK)
	if openedRevision.Revision.Version != 1 {
		t.Fatalf("opened revision version = %d", openedRevision.Revision.Version)
	}
	if string(openedRevision.Revision.State) != `{"companies":[],"digestCover":"data:image/png;base64,AAA","letter":{"paragraphs":"One","title":"Initial"}}` {
		t.Fatalf("opened revision state = %s", openedRevision.Revision.State)
	}

	rolledBack := postJSON[digestResponse](t, server, http.MethodPost, "/api/digests/"+created.Digest.ID+"/rollback", login.Token, map[string]any{
		"revisionId": revisions.Revisions[0].ID,
	}, http.StatusOK)
	if rolledBack.Digest.CurrentVersion != 3 {
		t.Fatalf("rollback version = %d", rolledBack.Digest.CurrentVersion)
	}
	if string(rolledBack.Digest.State) != `{"companies":[],"digestCover":"data:image/png;base64,AAA","letter":{"paragraphs":"One","title":"Initial"}}` {
		t.Fatalf("rollback state = %s", rolledBack.Digest.State)
	}

	exported := getJSON[exportResponse](t, server, "/api/digests/"+created.Digest.ID+"/export", login.Token, http.StatusOK)
	if exported.SchemaVersion != 1 {
		t.Fatalf("schema version = %d", exported.SchemaVersion)
	}
	if string(exported.State) != string(rolledBack.Digest.State) {
		t.Fatalf("exported state = %s", exported.State)
	}

	imported := postJSON[digestResponse](t, server, http.MethodPost, "/api/digests/import", login.Token, map[string]any{
		"title": "Imported digest",
		"state": exported.State,
	}, http.StatusCreated)
	if imported.Digest.ID == created.Digest.ID {
		t.Fatalf("import reused original digest id")
	}
	if string(imported.Digest.State) != string(exported.State) {
		t.Fatalf("imported state = %s", imported.Digest.State)
	}
}

func TestDigestDeleteAndRevisionPrivacy(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour})

	owner := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/register", "", map[string]any{
		"email":    "owner@example.com",
		"password": "secret-123",
	}, http.StatusCreated)
	other := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/register", "", map[string]any{
		"email":    "other@example.com",
		"password": "secret-123",
	}, http.StatusCreated)

	created := postJSON[digestResponse](t, server, http.MethodPost, "/api/digests", owner.Token, map[string]any{
		"title": "Private project",
		"state": map[string]any{"letter": map[string]any{"title": "Private"}},
	}, http.StatusCreated)
	saved := postJSON[revisionResponse](t, server, http.MethodPut, "/api/digests/"+created.Digest.ID+"/autosave", owner.Token, map[string]any{
		"title":  "Private project",
		"state":  map[string]any{"letter": map[string]any{"title": "Private v2"}},
		"action": "typed",
	}, http.StatusOK)

	getJSON[errorResponse](t, server, "/api/digests/"+created.Digest.ID+"/revisions/"+saved.Revision.ID, other.Token, http.StatusNotFound)
	deleteDigest(t, server, created.Digest.ID, other.Token, http.StatusNotFound)

	deleteDigest(t, server, created.Digest.ID, owner.Token, http.StatusNoContent)
	getJSON[errorResponse](t, server, "/api/digests/"+created.Digest.ID, owner.Token, http.StatusNotFound)
	getJSON[errorResponse](t, server, "/api/digests/"+created.Digest.ID+"/revisions", owner.Token, http.StatusNotFound)

	listed := getJSON[digestsResponse](t, server, "/api/digests", owner.Token, http.StatusOK)
	if len(listed.Digests) != 0 {
		t.Fatalf("deleted digest still listed: %+v", listed.Digests)
	}
}

func TestDigestRoutesRequireAuth(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour})

	getJSON[errorResponse](t, server, "/api/digests", "", http.StatusUnauthorized)
	postJSON[errorResponse](t, server, http.MethodPost, "/api/digests", "", map[string]any{
		"title": "No auth",
		"state": map[string]any{},
	}, http.StatusUnauthorized)
}

func TestAdminCanDeleteManagedUsers(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour})

	admin := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/register", "", map[string]any{
		"email":    "admin@example.com",
		"password": "secret-123",
	}, http.StatusCreated)
	created := postJSON[map[string]User](t, server, http.MethodPost, "/api/admin/users", admin.Token, map[string]any{
		"name": "Managed user",
	}, http.StatusCreated)
	managed := created["user"]
	if managed.ID == "" || managed.AccessCode == "" {
		t.Fatalf("managed user missing id or access code: %+v", managed)
	}

	deleteUser(t, server, managed.ID, admin.Token, http.StatusNoContent)

	listed := getJSON[adminUsersResponse](t, server, "/api/admin/users", admin.Token, http.StatusOK)
	for _, user := range listed.Users {
		if user.ID == managed.ID {
			t.Fatalf("deleted user still listed: %+v", user)
		}
	}
	postJSON[errorResponse](t, server, http.MethodPost, "/api/auth/login", "", map[string]any{
		"code": managed.AccessCode,
	}, http.StatusUnauthorized)
}

func TestAdminDeleteUserRequiresAdminAndDoesNotDeleteSelf(t *testing.T) {
	server := NewServer(NewMemoryStore(), Config{SessionTTL: time.Hour})

	admin := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/register", "", map[string]any{
		"email":    "admin@example.com",
		"password": "secret-123",
	}, http.StatusCreated)
	regular := postJSON[authResponse](t, server, http.MethodPost, "/api/auth/register", "", map[string]any{
		"email":    "regular@example.com",
		"password": "secret-123",
	}, http.StatusCreated)
	created := postJSON[map[string]User](t, server, http.MethodPost, "/api/admin/users", admin.Token, map[string]any{
		"name": "Managed user",
	}, http.StatusCreated)
	managed := created["user"]

	deleteUser(t, server, managed.ID, regular.Token, http.StatusForbidden)
	deleteUser(t, server, admin.User.ID, admin.Token, http.StatusForbidden)

	listed := getJSON[adminUsersResponse](t, server, "/api/admin/users", admin.Token, http.StatusOK)
	foundManaged := false
	foundAdmin := false
	for _, user := range listed.Users {
		if user.ID == managed.ID {
			foundManaged = true
		}
		if user.ID == admin.User.ID {
			foundAdmin = true
		}
	}
	if !foundManaged {
		t.Fatalf("managed user was deleted by non-admin")
	}
	if !foundAdmin {
		t.Fatalf("admin self-delete removed admin")
	}
}

func postJSON[T any](t *testing.T, server *Server, method, path, token string, body any, wantStatus int) T {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	server.Routes().ServeHTTP(res, req)

	if res.Code != wantStatus {
		t.Fatalf("%s %s status = %d, body = %s", method, path, res.Code, res.Body.String())
	}
	var out T
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, res.Body.String())
	}
	return out
}

func deleteDigest(t *testing.T, server *Server, digestID, token string, wantStatus int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/digests/"+digestID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	server.Routes().ServeHTTP(res, req)
	if res.Code != wantStatus {
		t.Fatalf("DELETE /api/digests/%s status = %d, body = %s", digestID, res.Code, res.Body.String())
	}
}

func deleteUser(t *testing.T, server *Server, userID, token string, wantStatus int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+userID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	server.Routes().ServeHTTP(res, req)
	if res.Code != wantStatus {
		t.Fatalf("DELETE /api/admin/users/%s status = %d, body = %s", userID, res.Code, res.Body.String())
	}
}

func getJSON[T any](t *testing.T, server *Server, path, token string, wantStatus int) T {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	server.Routes().ServeHTTP(res, req)

	if res.Code != wantStatus {
		t.Fatalf("GET %s status = %d, body = %s", path, res.Code, res.Body.String())
	}
	var out T
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, res.Body.String())
	}
	return out
}
