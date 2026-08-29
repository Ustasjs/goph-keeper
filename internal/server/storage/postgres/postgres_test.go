package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ustasjs/goph-keeper/internal/secret"
	"github.com/ustasjs/goph-keeper/internal/server/auth"
	"github.com/ustasjs/goph-keeper/migrations"
)

// newTestStorage connects to the database from DATABASE_DSN and
// applies the migrations. Without the variable the test is
// skipped, so plain "go test" works with no database around.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		t.Skip("DATABASE_DSN is not set")
	}

	require.NoError(t, migrations.Run(dsn))

	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return New(pool)
}

func testUser(t *testing.T, s *Storage) string {
	t.Helper()

	userID, err := s.CreateUser(context.Background(), auth.NewUser{
		// Unique login: tests share one database.
		Login:        "user-" + uuid.New().String(),
		PasswordHash: "$argon2id$fake",
		Crypto: auth.CryptoBundle{
			KEKSalt:      []byte("salt"),
			KDFParams:    auth.KDFParams{MemoryKiB: 65536, Time: 1, Threads: 4},
			EncryptedDEK: []byte("wrapped-dek"),
		},
	})
	require.NoError(t, err)
	return userID
}

func TestStorage_CreateUser_loginTaken(t *testing.T) {
	s := newTestStorage(t)
	login := "user-" + uuid.New().String()
	newUser := auth.NewUser{
		Login:        login,
		PasswordHash: "hash",
		Crypto: auth.CryptoBundle{
			KEKSalt:      []byte("salt"),
			KDFParams:    auth.KDFParams{MemoryKiB: 1, Time: 1, Threads: 1},
			EncryptedDEK: []byte("dek"),
		},
	}

	_, err := s.CreateUser(context.Background(), newUser)
	require.NoError(t, err)

	_, err = s.CreateUser(context.Background(), newUser)
	assert.ErrorIs(t, err, auth.ErrLoginTaken)
}

func TestStorage_UserByLogin_roundTrip(t *testing.T) {
	s := newTestStorage(t)
	login := "user-" + uuid.New().String()
	want := auth.NewUser{
		Login:        login,
		PasswordHash: "$argon2id$some-hash",
		Crypto: auth.CryptoBundle{
			KEKSalt:      []byte("kek-salt"),
			KDFParams:    auth.KDFParams{MemoryKiB: 65536, Time: 1, Threads: 4},
			EncryptedDEK: []byte("wrapped-dek"),
		},
	}

	userID, err := s.CreateUser(context.Background(), want)
	require.NoError(t, err)

	got, err := s.UserByLogin(context.Background(), login)
	require.NoError(t, err)
	assert.Equal(t, userID, got.ID)
	assert.Equal(t, want.Login, got.Login)
	assert.Equal(t, want.PasswordHash, got.PasswordHash)
	assert.Equal(t, want.Crypto, got.Crypto)
}

func TestStorage_UserByLogin_notFound(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.UserByLogin(context.Background(), "no-such-login")
	assert.ErrorIs(t, err, auth.ErrUserNotFound)
}

func TestStorage_Secrets_crud(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	userID := testUser(t, s)

	created, err := s.CreateSecret(ctx, userID, secret.NewSecret{
		Type:     secret.TypeLoginPassword,
		Name:     "github",
		Metadata: "work account",
		Payload:  []byte("encrypted-blob"),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), created.Version)

	got, err := s.SecretByID(ctx, userID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.TypeLoginPassword, got.Type)
	assert.Equal(t, "github", got.Name)
	assert.Equal(t, "work account", got.Metadata)
	assert.Equal(t, []byte("encrypted-blob"), got.Payload)

	// Update bumps the version and replaces the fields.
	version, err := s.UpdateSecret(ctx, userID, secret.Update{
		ID:       created.ID,
		Name:     "github-renamed",
		Metadata: "personal",
		Payload:  []byte("new-blob"),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), version)

	list, err := s.ListSecrets(ctx, userID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "github-renamed", list[0].Name)

	// Soft delete hides the record from every read.
	require.NoError(t, s.DeleteSecret(ctx, userID, created.ID))

	_, err = s.SecretByID(ctx, userID, created.ID)
	assert.ErrorIs(t, err, secret.ErrNotFound)

	list, err = s.ListSecrets(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, list)

	// Deleting again reports not found.
	assert.ErrorIs(t, s.DeleteSecret(ctx, userID, created.ID), secret.ErrNotFound)
}

func TestStorage_Secrets_ownership(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	owner := testUser(t, s)
	stranger := testUser(t, s)

	created, err := s.CreateSecret(ctx, owner, secret.NewSecret{
		Type:    secret.TypeText,
		Name:    "note",
		Payload: []byte("blob"),
	})
	require.NoError(t, err)

	// Another user must not see or touch the record.
	_, err = s.SecretByID(ctx, stranger, created.ID)
	assert.ErrorIs(t, err, secret.ErrNotFound)

	_, err = s.UpdateSecret(ctx, stranger, secret.Update{
		ID: created.ID, Name: "hacked", Payload: []byte("x"),
	})
	assert.ErrorIs(t, err, secret.ErrNotFound)

	assert.ErrorIs(t, s.DeleteSecret(ctx, stranger, created.ID), secret.ErrNotFound)
}
