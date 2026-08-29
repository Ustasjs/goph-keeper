package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	"github.com/ustasjs/goph-keeper/internal/secret"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	s, err := New(filepath.Join(t.TempDir(), "gophkeeper"))
	require.NoError(t, err)
	return s
}

func TestNew_createsPrivateDir(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "gophkeeper")
	s, err := New(dir)
	require.NoError(t, err)
	assert.Equal(t, dir, s.Dir())

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(dirMode), info.Mode().Perm(),
		"only the owner may enter the state dir")
}

func TestNew_defaultDirFromEnv(t *testing.T) {
	// No t.Parallel: the test sets an environment variable.
	dir := filepath.Join(t.TempDir(), "custom-home")
	t.Setenv("GOPHKEEPER_HOME", dir)

	s, err := New("")
	require.NoError(t, err)
	assert.Equal(t, dir, s.Dir())
}

func TestToken_roundTrip(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)

	// No token yet: empty string, not an error.
	got, err := s.Token()
	require.NoError(t, err)
	assert.Empty(t, got)

	require.NoError(t, s.SaveToken("first-token"))
	got, err = s.Token()
	require.NoError(t, err)
	assert.Equal(t, "first-token", got)

	// The sliding session rewrites the token on every answer.
	require.NoError(t, s.SaveToken("fresh-token"))
	got, err = s.Token()
	require.NoError(t, err)
	assert.Equal(t, "fresh-token", got)
}

func TestFiles_arePrivate(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	require.NoError(t, s.SaveToken("token"))
	require.NoError(t, s.SaveSession(Session{Login: "alice"}))
	require.NoError(t, s.SaveCache(nil, time.Now()))

	for _, name := range []string{tokenFile, sessionFile, cacheFile} {
		info, err := os.Stat(filepath.Join(s.Dir(), name))
		require.NoError(t, err, name)
		assert.Equal(t, os.FileMode(fileMode), info.Mode().Perm(),
			"%s must be readable by the owner only", name)
	}
}

func TestSession_roundTrip(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)

	_, err := s.Session()
	assert.ErrorIs(t, err, ErrNoSession)

	want := Session{
		Login:        "alice",
		KEKSalt:      []byte("random-salt"),
		KDFParams:    crypt.DefaultKDFParams(),
		EncryptedDEK: []byte("wrapped-dek"),
	}
	require.NoError(t, s.SaveSession(want))

	got, err := s.Session()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSession_UnlockDEK(t *testing.T) {
	t.Parallel()

	const masterPassword = "correct horse battery staple"

	salt, err := crypt.NewSalt()
	require.NoError(t, err)
	params := crypt.DefaultKDFParams()
	kek, err := crypt.DeriveKEK(masterPassword, salt, params)
	require.NoError(t, err)
	dek, err := crypt.NewDEK()
	require.NoError(t, err)
	wrapped, err := crypt.WrapDEK(dek, kek)
	require.NoError(t, err)

	s := newTestStore(t)
	require.NoError(t, s.SaveSession(Session{
		Login:        "alice",
		KEKSalt:      salt,
		KDFParams:    params,
		EncryptedDEK: wrapped,
	}))

	session, err := s.Session()
	require.NoError(t, err)

	got, err := session.UnlockDEK(masterPassword)
	require.NoError(t, err)
	assert.Equal(t, dek, got, "the same data key comes back after a restart")

	_, err = session.UnlockDEK("wrong password")
	assert.ErrorIs(t, err, crypt.ErrWrongMasterPassword)
}

func TestCache_roundTrip(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)

	// Nothing synced yet.
	cache, err := s.Cache()
	require.NoError(t, err)
	assert.Empty(t, cache.Secrets)
	assert.True(t, cache.SyncedAt.IsZero())

	syncedAt := time.Now().UTC().Truncate(time.Second)
	secrets := []secret.Secret{
		{ID: "id-1", Type: secret.TypeText, Name: "note", Payload: []byte("encrypted"), Version: 2},
		{ID: "id-2", Type: secret.TypeCard, Name: "visa", Metadata: "bank", Version: 1},
	}
	require.NoError(t, s.SaveCache(secrets, syncedAt))

	cache, err = s.Cache()
	require.NoError(t, err)
	assert.Equal(t, secrets, cache.Secrets)
	assert.True(t, syncedAt.Equal(cache.SyncedAt))
}

func TestCache_replacedByFullSnapshot(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	now := time.Now()

	require.NoError(t, s.SaveCache([]secret.Secret{
		{ID: "id-1", Name: "kept"},
		{ID: "id-2", Name: "deleted on another client"},
	}, now))

	// A new snapshot replaces the old one, so records removed
	// elsewhere disappear here too.
	require.NoError(t, s.SaveCache([]secret.Secret{{ID: "id-1", Name: "kept"}}, now))

	cache, err := s.Cache()
	require.NoError(t, err)
	require.Len(t, cache.Secrets, 1)
	assert.Equal(t, "id-1", cache.Secrets[0].ID)
}

func TestClear(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	require.NoError(t, s.SaveToken("token"))
	require.NoError(t, s.SaveSession(Session{Login: "alice"}))
	require.NoError(t, s.SaveCache([]secret.Secret{{ID: "id-1"}}, time.Now()))

	require.NoError(t, s.Clear())

	token, err := s.Token()
	require.NoError(t, err)
	assert.Empty(t, token)

	_, err = s.Session()
	assert.ErrorIs(t, err, ErrNoSession)

	cache, err := s.Cache()
	require.NoError(t, err)
	assert.Empty(t, cache.Secrets)

	// Clearing an empty store is fine.
	assert.NoError(t, s.Clear())
}

func TestWrite_leavesNoTempFiles(t *testing.T) {
	t.Parallel()

	s := newTestStore(t)
	require.NoError(t, s.SaveToken("token"))
	require.NoError(t, s.SaveToken("another token"))

	entries, err := os.ReadDir(s.Dir())
	require.NoError(t, err)
	assert.Len(t, entries, 1, "writes must not leave temp files behind")
}
