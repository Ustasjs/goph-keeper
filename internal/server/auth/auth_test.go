package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeUserRepo struct {
	created  *NewUser
	createID string
	user     User
	err      error
}

func (f *fakeUserRepo) CreateUser(_ context.Context, user NewUser) (string, error) {
	f.created = &user
	if f.err != nil {
		return "", f.err
	}
	return f.createID, nil
}

func (f *fakeUserRepo) UserByLogin(_ context.Context, _ string) (User, error) {
	if f.err != nil {
		return User{}, f.err
	}
	return f.user, nil
}

type fakeTokenIssuer struct{}

func (fakeTokenIssuer) Generate(userID string) (string, error) {
	return "token-for-" + userID, nil
}

func testCrypto() CryptoBundle {
	return CryptoBundle{
		KEKSalt:      []byte("salt"),
		KDFParams:    KDFParams{MemoryKiB: 64 * 1024, Time: 1, Threads: 4},
		EncryptedDEK: []byte("wrapped-dek"),
	}
}

func TestService_Register_storesHashNotPassword(t *testing.T) {
	t.Parallel()

	repo := &fakeUserRepo{createID: "user-1"}
	svc := New(repo, fakeTokenIssuer{})

	authToken, err := svc.Register(context.Background(), "alice", "secret-password", testCrypto())
	require.NoError(t, err)
	assert.Equal(t, "token-for-user-1", authToken)

	require.NotNil(t, repo.created)
	assert.Equal(t, "alice", repo.created.Login)
	assert.Equal(t, testCrypto(), repo.created.Crypto)

	// The repo must get a verifiable hash, never the password.
	assert.NotContains(t, repo.created.PasswordHash, "secret-password")
	ok, err := verifyPassword(repo.created.PasswordHash, "secret-password")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestService_Register_loginTaken(t *testing.T) {
	t.Parallel()

	repo := &fakeUserRepo{err: ErrLoginTaken}
	svc := New(repo, fakeTokenIssuer{})

	_, err := svc.Register(context.Background(), "alice", "password", testCrypto())
	assert.ErrorIs(t, err, ErrLoginTaken)
}

func TestService_Login_success(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("right password")
	require.NoError(t, err)
	repo := &fakeUserRepo{user: User{ID: "user-1", Login: "alice", PasswordHash: hash, Crypto: testCrypto()}}
	svc := New(repo, fakeTokenIssuer{})

	authToken, crypto, err := svc.Login(context.Background(), "alice", "right password")
	require.NoError(t, err)
	assert.Equal(t, "token-for-user-1", authToken)
	assert.Equal(t, testCrypto(), crypto)
}

func TestService_Login_wrongPassword(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("right password")
	require.NoError(t, err)
	repo := &fakeUserRepo{user: User{ID: "user-1", PasswordHash: hash}}
	svc := New(repo, fakeTokenIssuer{})

	_, _, err = svc.Login(context.Background(), "alice", "wrong password")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestService_Login_unknownLogin(t *testing.T) {
	t.Parallel()

	repo := &fakeUserRepo{err: ErrUserNotFound}
	svc := New(repo, fakeTokenIssuer{})

	// Unknown login and wrong password must be one error, so the
	// answer does not leak which logins exist.
	_, _, err := svc.Login(context.Background(), "nobody", "password")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}
