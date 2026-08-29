package remote

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	"github.com/ustasjs/goph-keeper/internal/secret"
)

func testBundle(t *testing.T) CryptoBundle {
	t.Helper()

	salt, err := crypt.NewSalt()
	require.NoError(t, err)
	return CryptoBundle{
		KEKSalt:      salt,
		KDFParams:    crypt.DefaultKDFParams(),
		EncryptedDEK: []byte("wrapped-dek"),
	}
}

func TestClient_Register(t *testing.T) {
	t.Parallel()

	t.Run("saves the token", func(t *testing.T) {
		t.Parallel()

		client, tokens, _ := newTestClient(t)

		require.NoError(t, client.Register(context.Background(), "alice", "password", testBundle(t)))
		assert.Equal(t, "token-for-user-1", tokens.token)
	})

	t.Run("login taken", func(t *testing.T) {
		t.Parallel()

		client, _, srv := newTestClient(t)
		srv.registerErr = errTaken

		err := client.Register(context.Background(), "alice", "password", testBundle(t))
		assert.ErrorIs(t, err, ErrLoginTaken)
	})
}

func TestClient_Login(t *testing.T) {
	t.Parallel()

	t.Run("returns crypto material", func(t *testing.T) {
		t.Parallel()

		client, tokens, srv := newTestClient(t)
		want := testBundle(t)
		srv.bundle = want

		got, err := client.Login(context.Background(), "alice", "password")
		require.NoError(t, err)
		assert.Equal(t, want.KEKSalt, got.KEKSalt)
		assert.Equal(t, want.EncryptedDEK, got.EncryptedDEK)
		assert.Equal(t, want.KDFParams, got.KDFParams)
		assert.Equal(t, "token-for-user-1", tokens.token)
	})

	t.Run("wrong password", func(t *testing.T) {
		t.Parallel()

		client, _, srv := newTestClient(t)
		srv.loginErr = errBadCredentials

		_, err := client.Login(context.Background(), "alice", "bad")
		// For Login the same gRPC code must read as bad
		// credentials, not as an expired session.
		assert.ErrorIs(t, err, ErrInvalidCredentials)
		assert.NotErrorIs(t, err, ErrUnauthenticated)
	})
}

func TestClient_Secrets_crud(t *testing.T) {
	t.Parallel()

	client, tokens, srv := newTestClient(t)
	srv.token = "valid-token"
	require.NoError(t, tokens.SaveToken("valid-token"))
	ctx := context.Background()

	id, err := client.CreateSecret(ctx, secret.NewSecret{
		Type:     secret.TypeCard,
		Name:     "visa",
		Metadata: "bank",
		Payload:  []byte("encrypted"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	got, err := client.GetSecret(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, secret.TypeCard, got.Type)
	assert.Equal(t, "visa", got.Name)
	assert.Equal(t, "bank", got.Metadata)
	assert.Equal(t, []byte("encrypted"), got.Payload)

	list, err := client.ListSecrets(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, id, list[0].ID)

	require.NoError(t, client.UpdateSecret(ctx, secret.Update{
		ID: id, Name: "visa-renamed", Payload: []byte("new"),
	}))
	got, err = client.GetSecret(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "visa-renamed", got.Name)

	require.NoError(t, client.DeleteSecret(ctx, id))
	_, err = client.GetSecret(ctx, id)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestClient_CreateSecret_unknownType(t *testing.T) {
	t.Parallel()

	client, _, _ := newTestClient(t)

	_, err := client.CreateSecret(context.Background(), secret.NewSecret{
		Type: "no-such-type", Name: "x", Payload: []byte("blob"),
	})
	assert.Error(t, err)
}

func TestClient_slidingToken(t *testing.T) {
	t.Parallel()

	client, tokens, srv := newTestClient(t)
	srv.token = "old-token"
	require.NoError(t, tokens.SaveToken("old-token"))
	srv.freshToken = "fresh-token"

	_, err := client.ListSecrets(context.Background())
	require.NoError(t, err)

	// The server sent a new token in the answer header and the
	// client saved it: the session keeps sliding.
	assert.Equal(t, "fresh-token", tokens.token)
	// And the call carried the old one.
	assert.Equal(t, "old-token", srv.gotToken)
}

func TestClient_unauthenticated(t *testing.T) {
	t.Parallel()

	client, _, srv := newTestClient(t)
	srv.token = "only-this-token-works"

	_, err := client.ListSecrets(context.Background())
	assert.ErrorIs(t, err, ErrUnauthenticated)
}

func TestClient_serverDown(t *testing.T) {
	t.Parallel()

	client, _, srv := newTestClient(t)
	srv.stop()

	// Read commands use this error to fall back to the cache.
	_, err := client.ListSecrets(context.Background())
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestWrapError_nil(t *testing.T) {
	t.Parallel()

	assert.NoError(t, wrapError("op", nil))
}

func TestWrapError_plainError(t *testing.T) {
	t.Parallel()

	err := wrapError("op", errors.New("something broke"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "something broke")
}
