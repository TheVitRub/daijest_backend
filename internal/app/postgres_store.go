package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) CreateUser(ctx context.Context, email, name, passwordHash string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (email, name, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id::text, email, name, password_hash, created_at
	`, email, name, passwordHash)
	return scanUser(row)
}

func (s *PostgresStore) FindUserByEmail(ctx context.Context, email string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, email, name, password_hash, created_at
		FROM users
		WHERE email = $1
	`, email)
	return scanUser(row)
}

func (s *PostgresStore) CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt)
	return err
}

func (s *PostgresStore) FindUserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id::text, u.email, u.name, u.password_hash, u.created_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2
	`, tokenHash, now)
	return scanUser(row)
}

func (s *PostgresStore) ListDigests(ctx context.Context, userID string) ([]Digest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, user_id::text, title, current_version, current_state, created_at, updated_at
		FROM digests
		WHERE user_id = $1
		ORDER BY updated_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var digests []Digest
	for rows.Next() {
		digest, err := scanDigest(rows)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digest)
	}
	return digests, rows.Err()
}

func (s *PostgresStore) CreateDigest(ctx context.Context, userID, title string, state json.RawMessage, action string) (Digest, Revision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Digest{}, Revision{}, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
		INSERT INTO digests (user_id, title, current_version, current_state)
		VALUES ($1, $2, 1, $3)
		RETURNING id::text, user_id::text, title, current_version, current_state, created_at, updated_at
	`, userID, title, state)
	digest, err := scanDigest(row)
	if err != nil {
		return Digest{}, Revision{}, err
	}

	row = tx.QueryRowContext(ctx, `
		INSERT INTO digest_revisions (digest_id, user_id, version, action, state)
		VALUES ($1, $2, 1, $3, $4)
		RETURNING id::text, digest_id::text, version, action, state, created_at
	`, digest.ID, userID, action, state)
	revision, err := scanRevision(row)
	if err != nil {
		return Digest{}, Revision{}, err
	}
	return digest, revision, tx.Commit()
}

func (s *PostgresStore) GetDigest(ctx context.Context, userID, digestID string) (Digest, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, user_id::text, title, current_version, current_state, created_at, updated_at
		FROM digests
		WHERE id = $1 AND user_id = $2
	`, digestID, userID)
	return scanDigest(row)
}

func (s *PostgresStore) AutosaveDigest(ctx context.Context, userID, digestID, title string, state json.RawMessage, action string) (Digest, Revision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Digest{}, Revision{}, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
		UPDATE digests
		SET title = $3,
		    current_version = current_version + 1,
		    current_state = $4,
		    updated_at = now()
		WHERE id = $1 AND user_id = $2
		RETURNING id::text, user_id::text, title, current_version, current_state, created_at, updated_at
	`, digestID, userID, title, state)
	digest, err := scanDigest(row)
	if err != nil {
		return Digest{}, Revision{}, err
	}

	row = tx.QueryRowContext(ctx, `
		INSERT INTO digest_revisions (digest_id, user_id, version, action, state)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text, digest_id::text, version, action, state, created_at
	`, digest.ID, userID, digest.CurrentVersion, action, state)
	revision, err := scanRevision(row)
	if err != nil {
		return Digest{}, Revision{}, err
	}
	return digest, revision, tx.Commit()
}

func (s *PostgresStore) ListRevisions(ctx context.Context, userID, digestID string) ([]Revision, error) {
	if _, err := s.GetDigest(ctx, userID, digestID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, digest_id::text, version, action, state, created_at
		FROM digest_revisions
		WHERE digest_id = $1 AND user_id = $2
		ORDER BY version ASC
	`, digestID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var revisions []Revision
	for rows.Next() {
		revision, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		revisions = append(revisions, revision)
	}
	return revisions, rows.Err()
}

func (s *PostgresStore) GetRevision(ctx context.Context, userID, digestID, revisionID string) (Revision, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, digest_id::text, version, action, state, created_at
		FROM digest_revisions
		WHERE id = $1 AND digest_id = $2 AND user_id = $3
	`, revisionID, digestID, userID)
	return scanRevision(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.Name, &user.PasswordHash, &user.CreatedAt)
	return user, mapSQLError(err)
}

func scanDigest(row scanner) (Digest, error) {
	var digest Digest
	var raw []byte
	err := row.Scan(&digest.ID, &digest.UserID, &digest.Title, &digest.CurrentVersion, &raw, &digest.CreatedAt, &digest.UpdatedAt)
	digest.State = cloneRaw(raw)
	return digest, mapSQLError(err)
}

func scanRevision(row scanner) (Revision, error) {
	var revision Revision
	var raw []byte
	err := row.Scan(&revision.ID, &revision.DigestID, &revision.Version, &revision.Action, &raw, &revision.CreatedAt)
	revision.State = cloneRaw(raw)
	return revision, mapSQLError(err)
}

func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}
