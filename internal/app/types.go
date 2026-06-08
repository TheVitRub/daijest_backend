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

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Digest struct {
	ID             string          `json:"id"`
	UserID         string          `json:"-"`
	Title          string          `json:"title"`
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
	CreateUser(ctx context.Context, email, name, passwordHash string) (User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
	CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	FindUserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error)
	ListDigests(ctx context.Context, userID string) ([]Digest, error)
	CreateDigest(ctx context.Context, userID, title string, state json.RawMessage, action string) (Digest, Revision, error)
	GetDigest(ctx context.Context, userID, digestID string) (Digest, error)
	AutosaveDigest(ctx context.Context, userID, digestID, title string, state json.RawMessage, action string) (Digest, Revision, error)
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
