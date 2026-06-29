package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var dataURLPattern = regexp.MustCompile(`data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})`)

type mediaRef struct {
	ID          string
	ContentType string
	Size        int64
	SHA256      string
}

type migrator struct {
	tx           *sql.Tx
	mediaDir     string
	urlPrefix    string
	mediaBySHA   map[string][]mediaRef
	mediaCreated int
	urlsReplaced int
	bytesWritten int64
}

func main() {
	var databaseURL string
	var mediaDir string
	var urlPrefix string
	flag.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "Postgres URL")
	flag.StringVar(&mediaDir, "media-dir", getenv("MEDIA_DIR", "/media"), "filesystem media directory")
	flag.StringVar(&urlPrefix, "url-prefix", getenv("MEDIA_URL_PREFIX", "/daijest/api/media"), "URL prefix stored in JSON")
	flag.Parse()

	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if err := os.MkdirAll(mediaDir, 0o755); err != nil {
		log.Fatalf("create media dir: %v", err)
	}

	ctx := context.Background()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("ping db: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	m := &migrator{
		tx:         tx,
		mediaDir:   mediaDir,
		urlPrefix:  strings.TrimRight(urlPrefix, "/"),
		mediaBySHA: map[string][]mediaRef{},
	}
	if err := m.loadExistingMedia(ctx); err != nil {
		log.Fatalf("load existing media: %v", err)
	}

	digests, err := m.migrateDigests(ctx)
	if err != nil {
		log.Fatalf("migrate digests: %v", err)
	}
	revisions, err := m.migrateRevisions(ctx)
	if err != nil {
		log.Fatalf("migrate revisions: %v", err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("commit: %v", err)
	}

	fmt.Printf("digests_updated=%d\n", digests)
	fmt.Printf("revisions_updated=%d\n", revisions)
	fmt.Printf("data_urls_replaced=%d\n", m.urlsReplaced)
	fmt.Printf("media_created=%d\n", m.mediaCreated)
	fmt.Printf("bytes_written=%d\n", m.bytesWritten)
}

func (m *migrator) loadExistingMedia(ctx context.Context) error {
	rows, err := m.tx.QueryContext(ctx, `
		SELECT id::text, content_type, size, COALESCE(sha256, '')
		FROM media
		WHERE COALESCE(sha256, '') <> ''
		ORDER BY created_at ASC
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ref mediaRef
		if err := rows.Scan(&ref.ID, &ref.ContentType, &ref.Size, &ref.SHA256); err != nil {
			return err
		}
		m.mediaBySHA[ref.SHA256] = append(m.mediaBySHA[ref.SHA256], ref)
	}
	return rows.Err()
}

func (m *migrator) migrateDigests(ctx context.Context) (int, error) {
	rows, err := m.tx.QueryContext(ctx, `
		SELECT id::text, user_id::text, current_state::text
		FROM digests
		WHERE current_state::text LIKE '%data:image/%'
		ORDER BY updated_at ASC
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type row struct {
		ID     string
		UserID string
		State  string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.UserID, &r.State); err != nil {
			return 0, err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	updated := 0
	for _, r := range pending {
		next, changed, err := m.transformJSON(ctx, r.UserID, r.State)
		if err != nil {
			return updated, fmt.Errorf("digest %s: %w", r.ID, err)
		}
		if !changed {
			continue
		}
		if _, err := m.tx.ExecContext(ctx, `UPDATE digests SET current_state = $1::jsonb WHERE id = $2::uuid`, next, r.ID); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func (m *migrator) migrateRevisions(ctx context.Context) (int, error) {
	rows, err := m.tx.QueryContext(ctx, `
		SELECT id::text, user_id::text, state::text
		FROM digest_revisions
		WHERE state::text LIKE '%data:image/%'
		ORDER BY created_at ASC
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type row struct {
		ID     string
		UserID string
		State  string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.UserID, &r.State); err != nil {
			return 0, err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	updated := 0
	for _, r := range pending {
		next, changed, err := m.transformJSON(ctx, r.UserID, r.State)
		if err != nil {
			return updated, fmt.Errorf("revision %s: %w", r.ID, err)
		}
		if !changed {
			continue
		}
		if _, err := m.tx.ExecContext(ctx, `UPDATE digest_revisions SET state = $1::jsonb WHERE id = $2::uuid`, next, r.ID); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func (m *migrator) transformJSON(ctx context.Context, userID, raw string) (string, bool, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return "", false, err
	}
	next, changed, err := m.transformValue(ctx, userID, value)
	if err != nil {
		return "", false, err
	}
	if !changed {
		return raw, false, nil
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return "", false, err
	}
	return string(encoded), true, nil
}

func (m *migrator) transformValue(ctx context.Context, userID string, value any) (any, bool, error) {
	switch v := value.(type) {
	case string:
		next, changed, err := m.replaceDataURLsInString(ctx, userID, v)
		if err != nil {
			return value, false, err
		}
		return next, changed, nil
	case []any:
		changed := false
		for i, item := range v {
			next, itemChanged, err := m.transformValue(ctx, userID, item)
			if err != nil {
				return nil, false, err
			}
			if itemChanged {
				v[i] = next
				changed = true
			}
		}
		return v, changed, nil
	case map[string]any:
		changed := false
		for key, item := range v {
			next, itemChanged, err := m.transformValue(ctx, userID, item)
			if err != nil {
				return nil, false, err
			}
			if itemChanged {
				v[key] = next
				changed = true
			}
		}
		return v, changed, nil
	default:
		return value, false, nil
	}
}

func (m *migrator) replaceDataURLsInString(ctx context.Context, userID, value string) (string, bool, error) {
	matches := dataURLPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, false, nil
	}

	var out strings.Builder
	out.Grow(len(value))
	last := 0
	for _, match := range matches {
		out.WriteString(value[last:match[0]])
		contentType := value[match[2]:match[3]]
		raw := value[match[4]:match[5]]
		ref, err := m.mediaFromData(ctx, userID, contentType, raw)
		if err != nil {
			return "", false, err
		}
		m.urlsReplaced++
		out.WriteString(m.urlPrefix + "/" + ref.ID)
		last = match[1]
	}
	out.WriteString(value[last:])
	return out.String(), true, nil
}

func (m *migrator) mediaFromData(ctx context.Context, userID, contentType, raw string) (mediaRef, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return mediaRef{}, fmt.Errorf("decode %s data URL: %w", contentType, err)
	}
	if len(decoded) == 0 {
		return mediaRef{}, errors.New("empty data URL")
	}

	sum := sha256.Sum256(decoded)
	sha := hex.EncodeToString(sum[:])
	for _, ref := range m.mediaBySHA[sha] {
		if _, err := os.Stat(m.mediaPath(ref.ID)); err == nil {
			return ref, nil
		} else if !os.IsNotExist(err) {
			return mediaRef{}, err
		}
	}

	id, err := newUUID()
	if err != nil {
		return mediaRef{}, err
	}
	ref := mediaRef{
		ID:          id,
		ContentType: contentType,
		Size:        int64(len(decoded)),
		SHA256:      sha,
	}

	path := m.mediaPath(ref.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return mediaRef{}, err
	}
	if existing, err := os.ReadFile(path); err == nil && !bytes.Equal(existing, decoded) {
		return mediaRef{}, fmt.Errorf("media path collision: %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return mediaRef{}, err
	}
	if err := os.WriteFile(path, decoded, 0o644); err != nil {
		return mediaRef{}, err
	}

	_, err = m.tx.ExecContext(ctx, `
		INSERT INTO media (id, user_id, content_type, size, sha256, created_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
		ON CONFLICT (id) DO NOTHING
	`, ref.ID, userID, ref.ContentType, ref.Size, ref.SHA256, time.Now().UTC())
	if err != nil {
		_ = os.Remove(path)
		return mediaRef{}, err
	}

	m.mediaBySHA[sha] = append(m.mediaBySHA[sha], ref)
	m.mediaCreated++
	m.bytesWritten += ref.Size
	return ref, nil
}

func (m *migrator) mediaPath(id string) string {
	return filepath.Join(m.mediaDir, id[0:2], id[2:4], id)
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
