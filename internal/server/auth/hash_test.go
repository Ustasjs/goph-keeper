package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword_roundTrip(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("correct horse battery staple")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(hash, "$argon2id$"), "hash must be in PHC format: %s", hash)

	ok, err := verifyPassword(hash, "correct horse battery staple")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = verifyPassword(hash, "wrong password")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestHashPassword_uniqueSalt(t *testing.T) {
	t.Parallel()

	first, err := hashPassword("same password")
	require.NoError(t, err)
	second, err := hashPassword("same password")
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "two hashes of one password must differ by salt")
}

func TestVerifyPassword_malformedHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not phc", "plain-text"},
		{"wrong algorithm", "$bcrypt$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
		{"missing parts", "$argon2id$v=19$m=19456,t=2,p=1"},
		{"bad salt base64", "$argon2id$v=19$m=19456,t=2,p=1$???$aGFzaA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifyPassword(tt.hash, "password")
			assert.Error(t, err)
		})
	}
}
