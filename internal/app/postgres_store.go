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

// userColumns is the standard column list for all user SELECT queries.
const userColumns = `id::text, email, name, password_hash, access_code, is_admin, created_at`

func (s *PostgresStore) CreateUser(ctx context.Context, email, name, passwordHash string) (User, error) {
	// Becomes admin if no admin exists in the system yet.
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (email, name, password_hash, is_admin)
		SELECT $1, $2, $3, NOT EXISTS (SELECT 1 FROM users WHERE is_admin = true)
		RETURNING `+userColumns,
		email, name, passwordHash)
	return scanUser(row)
}

func (s *PostgresStore) FindUserByEmail(ctx context.Context, email string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+userColumns+`
		FROM users
		WHERE email = $1
	`, email)
	return scanUser(row)
}

func (s *PostgresStore) FindUserByCode(ctx context.Context, code string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+userColumns+`
		FROM users
		WHERE access_code = $1
	`, code)
	return scanUser(row)
}

func (s *PostgresStore) CreateManagedUser(ctx context.Context, name, accessCode string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (name, access_code)
		VALUES ($1, $2)
		RETURNING `+userColumns,
		name, accessCode)
	return scanUser(row)
}

func (s *PostgresStore) UpdateUserAdmin(ctx context.Context, userID string, isAdmin bool) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE users SET is_admin = $1 WHERE id = $2 RETURNING `+userColumns,
		isAdmin, userID)
	return scanUser(row)
}

func (s *PostgresStore) UpdateUserName(ctx context.Context, userID string, name string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE users SET name = $1 WHERE id = $2 RETURNING `+userColumns,
		name, userID)
	return scanUser(row)
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+userColumns+`
		FROM users
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *PostgresStore) DeleteUser(ctx context.Context, userID string) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM users
		WHERE id = $1
	`, userID)
	if err != nil {
		return mapSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
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
		SELECT u.id::text, u.email, u.name, u.password_hash, u.access_code, u.is_admin, u.created_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > $2
	`, tokenHash, now)
	return scanUser(row)
}

// digestColumns is the standard column list for all digest SELECT queries.
const digestColumns = `id::text, user_id::text, title, digest_type, current_version, current_state, created_at, updated_at`

func (s *PostgresStore) ListDigests(ctx context.Context, userID string) ([]Digest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+digestColumns+`
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

func (s *PostgresStore) CreateDigest(ctx context.Context, userID, title string, digestType DigestType, state json.RawMessage, action string) (Digest, Revision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Digest{}, Revision{}, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
		INSERT INTO digests (user_id, title, digest_type, current_version, current_state)
		VALUES ($1, $2, $3, 1, $4)
		RETURNING `+digestColumns,
		userID, title, string(digestType), state)
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
		SELECT `+digestColumns+`
		FROM digests
		WHERE id = $1 AND user_id = $2
	`, digestID, userID)
	return scanDigest(row)
}

func (s *PostgresStore) AutosaveDigest(ctx context.Context, userID, digestID, title string, digestType DigestType, state json.RawMessage, action string) (Digest, Revision, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Digest{}, Revision{}, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
		UPDATE digests
		SET title = $3,
		    digest_type = CASE WHEN $4 = '' THEN digest_type ELSE $4 END,
		    current_version = current_version + 1,
		    current_state = $5,
		    updated_at = now()
		WHERE id = $1 AND user_id = $2
		RETURNING `+digestColumns,
		digestID, userID, title, string(digestType), state)
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

func (s *PostgresStore) DeleteDigest(ctx context.Context, userID, digestID string) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM digests
		WHERE id = $1 AND user_id = $2
	`, digestID, userID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ListRevisions(ctx context.Context, userID, digestID string) ([]Revision, error) {
	if _, err := s.GetDigest(ctx, userID, digestID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, digest_id::text, version, action, created_at
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
		revision, err := scanRevisionMeta(rows)
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

func (s *PostgresStore) SaveMedia(ctx context.Context, m MediaMeta) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO media (id, user_id, content_type, size, sha256)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''))
	`, m.ID, m.UserID, m.ContentType, m.Size, m.SHA256)
	return mapSQLError(err)
}

func (s *PostgresStore) GetMedia(ctx context.Context, id string) (MediaMeta, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, user_id::text, content_type, size, COALESCE(sha256, ''), created_at
		FROM media
		WHERE id = $1
	`, id)
	var m MediaMeta
	err := row.Scan(&m.ID, &m.UserID, &m.ContentType, &m.Size, &m.SHA256, &m.CreatedAt)
	return m, mapSQLError(err)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var user User
	var email sql.NullString
	var pwHash sql.NullString
	var accessCode sql.NullString
	err := row.Scan(&user.ID, &email, &user.Name, &pwHash, &accessCode, &user.IsAdmin, &user.CreatedAt)
	user.Email = email.String
	user.PasswordHash = pwHash.String
	user.AccessCode = accessCode.String
	return user, mapSQLError(err)
}

func scanDigest(row scanner) (Digest, error) {
	var digest Digest
	var raw []byte
	var digestType string
	err := row.Scan(&digest.ID, &digest.UserID, &digest.Title, &digestType, &digest.CurrentVersion, &raw, &digest.CreatedAt, &digest.UpdatedAt)
	digest.DigestType = DigestType(digestType)
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

func scanRevisionMeta(row scanner) (Revision, error) {
	var revision Revision
	err := row.Scan(&revision.ID, &revision.DigestID, &revision.Version, &revision.Action, &revision.CreatedAt)
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
