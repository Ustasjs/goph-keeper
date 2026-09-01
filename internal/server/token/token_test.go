package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_roundTrip(t *testing.T) {
	t.Parallel()

	svc := New([]byte("test-secret"), time.Hour)

	tokenString, err := svc.Generate("user-1")
	require.NoError(t, err)

	userID, err := svc.ParseUserID(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user-1", userID)
}

func TestService_ParseUserID_wrongSecret(t *testing.T) {
	t.Parallel()

	tokenString, err := New([]byte("one secret"), time.Hour).Generate("user-1")
	require.NoError(t, err)

	_, err = New([]byte("other secret"), time.Hour).ParseUserID(tokenString)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestService_ParseUserID_expired(t *testing.T) {
	t.Parallel()

	svc := New([]byte("test-secret"), -time.Minute)
	tokenString, err := svc.Generate("user-1")
	require.NoError(t, err)

	_, err = svc.ParseUserID(tokenString)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestService_ParseUserID_garbage(t *testing.T) {
	t.Parallel()

	_, err := New([]byte("test-secret"), time.Hour).ParseUserID("not-a-jwt")
	assert.ErrorIs(t, err, ErrInvalidToken)
}
