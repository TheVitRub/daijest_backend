package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

type MemoryStore struct {
	mu        sync.Mutex
	users     map[string]User
	emailToID map[string]string
	codeToID  map[string]string
	sessions  map[string]memorySession
	digests   map[string]Digest
	revisions map[string][]Revision
	nextID    int
}

type memorySession struct {
	UserID    string
	ExpiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:     map[string]User{},
		emailToID: map[string]string{},
		codeToID:  map[string]string{},
		sessions:  map[string]memorySession{},
		digests:   map[string]Digest{},
		revisions: map[string][]Revision{},
	}
}

func (s *MemoryStore) CreateUser(_ context.Context, email, name, passwordHash string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.emailToID[email]; ok {
		return User{}, ErrConflict
	}
	user := User{
		ID:           s.newIDLocked("usr"),
		Email:        email,
		Name:         name,
		PasswordHash: passwordHash,
		IsAdmin:      !s.hasAdminLocked(),
		CreatedAt:    time.Now().UTC(),
	}
	s.users[user.ID] = user
	s.emailToID[email] = user.ID
	return user, nil
}

func (s *MemoryStore) FindUserByEmail(_ context.Context, email string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.emailToID[email]
	if !ok {
		return User{}, ErrNotFound
	}
	return s.users[id], nil
}

func (s *MemoryStore) FindUserByCode(_ context.Context, code string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.codeToID[code]
	if !ok {
		return User{}, ErrNotFound
	}
	return s.users[id], nil
}

func (s *MemoryStore) CreateManagedUser(_ context.Context, name, accessCode string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.codeToID[accessCode]; ok {
		return User{}, ErrConflict
	}
	user := User{
		ID:         s.newIDLocked("usr"),
		Name:       name,
		AccessCode: accessCode,
		IsAdmin:    false,
		CreatedAt:  time.Now().UTC(),
	}
	s.users[user.ID] = user
	s.codeToID[accessCode] = user.ID
	return user, nil
}

func (s *MemoryStore) UpdateUserAdmin(_ context.Context, userID string, isAdmin bool) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return User{}, ErrNotFound
	}
	user.IsAdmin = isAdmin
	s.users[userID] = user
	return user, nil
}

func (s *MemoryStore) DeleteUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return ErrNotFound
	}
	delete(s.users, userID)
	if user.Email != "" {
		delete(s.emailToID, user.Email)
	}
	if user.AccessCode != "" {
		delete(s.codeToID, user.AccessCode)
	}
	return nil
}

func (s *MemoryStore) ListUsers(_ context.Context) ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out, nil
}

func (s *MemoryStore) DeleteUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return ErrNotFound
	}
	if user.Email != "" {
		delete(s.emailToID, user.Email)
	}
	if user.AccessCode != "" {
		delete(s.codeToID, user.AccessCode)
	}
	for tokenHash, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, tokenHash)
		}
	}
	for digestID, digest := range s.digests {
		if digest.UserID == userID {
			delete(s.digests, digestID)
			delete(s.revisions, digestID)
		}
	}
	delete(s.users, userID)
	return nil
}

func (s *MemoryStore) CreateSession(_ context.Context, userID, tokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	s.sessions[tokenHash] = memorySession{UserID: userID, ExpiresAt: expiresAt}
	return nil
}

func (s *MemoryStore) FindUserBySession(_ context.Context, tokenHash string, now time.Time) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[tokenHash]
	if !ok || !session.ExpiresAt.After(now) {
		return User{}, ErrUnauthorized
	}
	user, ok := s.users[session.UserID]
	if !ok {
		return User{}, ErrUnauthorized
	}
	return user, nil
}

func (s *MemoryStore) ListDigests(_ context.Context, userID string) ([]Digest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Digest{}
	for _, digest := range s.digests {
		if digest.UserID == userID {
			out = append(out, digest)
		}
	}
	return out, nil
}

func (s *MemoryStore) CreateDigest(_ context.Context, userID, title string, digestType DigestType, state json.RawMessage, action string) (Digest, Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return Digest{}, Revision{}, ErrNotFound
	}
	now := time.Now().UTC()
	digest := Digest{
		ID:             s.newIDLocked("dig"),
		UserID:         userID,
		Title:          title,
		DigestType:     digestType,
		CurrentVersion: 1,
		State:          cloneRaw(state),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	revision := Revision{
		ID:        s.newIDLocked("rev"),
		DigestID:  digest.ID,
		Version:   1,
		Action:    action,
		State:     cloneRaw(state),
		CreatedAt: now,
	}
	s.digests[digest.ID] = digest
	s.revisions[digest.ID] = []Revision{revision}
	return digest, revision, nil
}

func (s *MemoryStore) GetDigest(_ context.Context, userID, digestID string) (Digest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.digests[digestID]
	if !ok || digest.UserID != userID {
		return Digest{}, ErrNotFound
	}
	digest.State = cloneRaw(digest.State)
	return digest, nil
}

func (s *MemoryStore) AutosaveDigest(_ context.Context, userID, digestID, title string, digestType DigestType, state json.RawMessage, action string) (Digest, Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.digests[digestID]
	if !ok || digest.UserID != userID {
		return Digest{}, Revision{}, ErrNotFound
	}
	now := time.Now().UTC()
	digest.Title = title
	if digestType != "" {
		digest.DigestType = digestType
	}
	digest.CurrentVersion++
	digest.State = cloneRaw(state)
	digest.UpdatedAt = now
	revision := Revision{
		ID:        s.newIDLocked("rev"),
		DigestID:  digest.ID,
		Version:   digest.CurrentVersion,
		Action:    action,
		State:     cloneRaw(state),
		CreatedAt: now,
	}
	s.digests[digest.ID] = digest
	s.revisions[digest.ID] = append(s.revisions[digest.ID], revision)
	return digest, revision, nil
}

func (s *MemoryStore) DeleteDigest(_ context.Context, userID, digestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.digests[digestID]
	if !ok || digest.UserID != userID {
		return ErrNotFound
	}
	delete(s.digests, digestID)
	delete(s.revisions, digestID)
	return nil
}

func (s *MemoryStore) ListRevisions(_ context.Context, userID, digestID string) ([]Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.digests[digestID]
	if !ok || digest.UserID != userID {
		return nil, ErrNotFound
	}
	revisions := append([]Revision(nil), s.revisions[digest.ID]...)
	return revisions, nil
}

func (s *MemoryStore) GetRevision(_ context.Context, userID, digestID, revisionID string) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.digests[digestID]
	if !ok || digest.UserID != userID {
		return Revision{}, ErrNotFound
	}
	for _, revision := range s.revisions[digestID] {
		if revision.ID == revisionID {
			revision.State = cloneRaw(revision.State)
			return revision, nil
		}
	}
	return Revision{}, ErrNotFound
}

func (s *MemoryStore) hasAdminLocked() bool {
	for _, u := range s.users {
		if u.IsAdmin {
			return true
		}
	}
	return false
}

func (s *MemoryStore) newIDLocked(prefix string) string {
	s.nextID++
	return prefix + "_" + itoa(s.nextID)
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}
