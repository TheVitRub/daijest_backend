package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrConflict     = errors.New("conflict")
	ErrNotFound     = errors.New("not found")
	ErrUnauthorized = errors.New("unauthorized")
)

type Config struct {
	SessionTTL time.Duration
}

// DigestType categorises a digest for display and filtering purposes.
type DigestType string

const (
	DigestTypeAnalytical   DigestType = "analytical"
	DigestTypeFarming      DigestType = "farming"
	DigestTypeCompanyGroup DigestType = "company_group"
)

func (t DigestType) Valid() bool {
	switch t {
	case DigestTypeAnalytical, DigestTypeFarming, DigestTypeCompanyGroup:
		return true
	}
	return false
}

// AllDigestTypes is the authoritative list returned by GET /api/digest-types.
var AllDigestTypes = []map[string]string{
	{"value": string(DigestTypeAnalytical), "label": "Аналитический"},
	{"value": string(DigestTypeFarming), "label": "Фермерский"},
	{"value": string(DigestTypeCompanyGroup), "label": "Группа компаний"},
}

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email,omitempty"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"`
	AccessCode   string    `json:"accessCode,omitempty"`
	IsAdmin      bool      `json:"isAdmin"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Digest struct {
	ID             string          `json:"id"`
	UserID         string          `json:"-"`
	Title          string          `json:"title"`
	DigestType     DigestType      `json:"digestType"`
	CurrentVersion int             `json:"currentVersion"`
	State          json.RawMessage `json:"state"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
}

type Revision struct {
	ID        string          `json:"id"`
	DigestID  string          `json:"digestId"`
	Version   int             `json:"version"`
	Action    string          `json:"action"`
	State     json.RawMessage `json:"state,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
}

type Store interface {
	// User management
	CreateUser(ctx context.Context, email, name, passwordHash string) (User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
	FindUserByCode(ctx context.Context, code string) (User, error)
	CreateManagedUser(ctx context.Context, name, accessCode string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUserAdmin(ctx context.Context, userID string, isAdmin bool) (User, error)
	DeleteUser(ctx context.Context, userID string) error

	// Session management
	CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	FindUserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error)

	// Digest management
	ListDigests(ctx context.Context, userID string) ([]Digest, error)
	CreateDigest(ctx context.Context, userID, title string, digestType DigestType, state json.RawMessage, action string) (Digest, Revision, error)
	GetDigest(ctx context.Context, userID, digestID string) (Digest, error)
	AutosaveDigest(ctx context.Context, userID, digestID, title string, digestType DigestType, state json.RawMessage, action string) (Digest, Revision, error)
	DeleteDigest(ctx context.Context, userID, digestID string) error
	ListRevisions(ctx context.Context, userID, digestID string) ([]Revision, error)
	GetRevision(ctx context.Context, userID, digestID, revisionID string) (Revision, error)
}

type authResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type digestResponse struct {
	Digest Digest `json:"digest"`
}

type digestsResponse struct {
	Digests []Digest `json:"digests"`
}

type revisionResponse struct {
	Revision Revision `json:"revision"`
}

type revisionsResponse struct {
	Revisions []Revision `json:"revisions"`
}

type exportResponse struct {
	SchemaVersion int             `json:"schemaVersion"`
	State         json.RawMessage `json:"state"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type adminUsersResponse struct {
	Users []User `json:"users"`
}
