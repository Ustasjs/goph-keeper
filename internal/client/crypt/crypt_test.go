package crypt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := NewDEK()
	require.NoError(t, err)
	return key
}

func TestEncrypt_roundTrip(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	plaintext := []byte(`{"login":"alice","password":"s3cret"}`)

	ciphertext, err := Encrypt(plaintext, key)
	require.NoError(t, err)

	got, err := Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncrypt_hidesPlaintext(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	plaintext := []byte("my-very-secret-password")

	ciphertext, err := Encrypt(plaintext, key)
	require.NoError(t, err)

	// The main promise of the whole project: the bytes that go
	// to the server carry no readable data.
	assert.False(t, bytes.Contains(ciphertext, plaintext),
		"ciphertext must not contain the plaintext")
}

func TestEncrypt_newNonceEveryTime(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	plaintext := []byte("same text")

	first, err := Encrypt(plaintext, key)
	require.NoError(t, err)
	second, err := Encrypt(plaintext, key)
	require.NoError(t, err)

	// A repeated nonce with one key breaks GCM, so two results
	// must differ.
	assert.NotEqual(t, first, second)
}

func TestDecrypt_wrongKey(t *testing.T) {
	t.Parallel()

	ciphertext, err := Encrypt([]byte("data"), testKey(t))
	require.NoError(t, err)

	_, err = Decrypt(ciphertext, testKey(t))
	assert.ErrorIs(t, err, ErrBadCiphertext)
}

func TestDecrypt_changedData(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	ciphertext, err := Encrypt([]byte("data to protect"), key)
	require.NoError(t, err)

	tests := []struct {
		name   string
		broken func([]byte) []byte
	}{
		{
			name: "flipped byte in ciphertext",
			broken: func(c []byte) []byte {
				out := bytes.Clone(c)
				out[len(out)-1] ^= 0xFF
				return out
			},
		},
		{
			name: "flipped byte in nonce",
			broken: func(c []byte) []byte {
				out := bytes.Clone(c)
				out[0] ^= 0xFF
				return out
			},
		},
		{
			name:   "cut short",
			broken: func(c []byte) []byte { return c[:5] },
		},
		{
			name:   "empty",
			broken: func([]byte) []byte { return nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Decrypt(tt.broken(ciphertext), key)
			assert.ErrorIs(t, err, ErrBadCiphertext)
		})
	}
}

func TestEncrypt_badKeySize(t *testing.T) {
	t.Parallel()

	_, err := Encrypt([]byte("data"), []byte("too short"))
	assert.ErrorIs(t, err, ErrBadKey)

	_, err = Decrypt([]byte("data"), []byte("too short"))
	assert.ErrorIs(t, err, ErrBadKey)
}

func TestDeriveKEK_sameInputSameKey(t *testing.T) {
	t.Parallel()

	salt, err := NewSalt()
	require.NoError(t, err)
	params := DefaultKDFParams()

	first, err := DeriveKEK("master password", salt, params)
	require.NoError(t, err)
	second, err := DeriveKEK("master password", salt, params)
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Len(t, first, KeyLen)
}

func TestDeriveKEK_differentInputDifferentKey(t *testing.T) {
	t.Parallel()

	salt, err := NewSalt()
	require.NoError(t, err)
	otherSalt, err := NewSalt()
	require.NoError(t, err)
	params := DefaultKDFParams()

	base, err := DeriveKEK("master password", salt, params)
	require.NoError(t, err)

	otherPassword, err := DeriveKEK("other password", salt, params)
	require.NoError(t, err)
	assert.NotEqual(t, base, otherPassword)

	otherSaltKey, err := DeriveKEK("master password", otherSalt, params)
	require.NoError(t, err)
	assert.NotEqual(t, base, otherSaltKey, "salt must change the key")
}

func TestDeriveKEK_badInput(t *testing.T) {
	t.Parallel()

	salt, err := NewSalt()
	require.NoError(t, err)

	_, err = DeriveKEK("password", nil, DefaultKDFParams())
	assert.Error(t, err, "empty salt")

	// Zero params would panic inside argon2.
	bad := []KDFParams{
		{MemoryKiB: 0, Time: 1, Threads: 4},
		{MemoryKiB: 64 * 1024, Time: 0, Threads: 4},
		{MemoryKiB: 64 * 1024, Time: 1, Threads: 0},
	}
	for _, params := range bad {
		_, err := DeriveKEK("password", salt, params)
		assert.Error(t, err, "params %+v", params)
	}
}

func TestWrapDEK_roundTrip(t *testing.T) {
	t.Parallel()

	salt, err := NewSalt()
	require.NoError(t, err)
	kek, err := DeriveKEK("master password", salt, DefaultKDFParams())
	require.NoError(t, err)
	dek, err := NewDEK()
	require.NoError(t, err)

	wrapped, err := WrapDEK(dek, kek)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(wrapped, dek), "wrapped DEK must hide the DEK")

	got, err := UnwrapDEK(wrapped, kek)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestUnwrapDEK_wrongMasterPassword(t *testing.T) {
	t.Parallel()

	salt, err := NewSalt()
	require.NoError(t, err)
	params := DefaultKDFParams()

	kek, err := DeriveKEK("right password", salt, params)
	require.NoError(t, err)
	dek, err := NewDEK()
	require.NoError(t, err)
	wrapped, err := WrapDEK(dek, kek)
	require.NoError(t, err)

	wrongKEK, err := DeriveKEK("wrong password", salt, params)
	require.NoError(t, err)

	// This is how the client checks the master password: the DEK
	// simply does not decrypt.
	_, err = UnwrapDEK(wrapped, wrongKEK)
	assert.ErrorIs(t, err, ErrWrongMasterPassword)
}

func TestFullFlow_registerThenLogin(t *testing.T) {
	t.Parallel()

	const masterPassword = "correct horse battery staple"
	secretData := []byte(`{"number":"4111111111111111","cvv":"123"}`)

	// Register: make the salt, the DEK and the wrapped DEK.
	salt, err := NewSalt()
	require.NoError(t, err)
	params := DefaultKDFParams()
	kek, err := DeriveKEK(masterPassword, salt, params)
	require.NoError(t, err)
	dek, err := NewDEK()
	require.NoError(t, err)
	wrappedDEK, err := WrapDEK(dek, kek)
	require.NoError(t, err)

	// Store a secret.
	stored, err := Encrypt(secretData, dek)
	require.NoError(t, err)

	// Login on another machine: the server returns salt, params
	// and the wrapped DEK; the master password opens everything.
	sameKEK, err := DeriveKEK(masterPassword, salt, params)
	require.NoError(t, err)
	sameDEK, err := UnwrapDEK(wrappedDEK, sameKEK)
	require.NoError(t, err)

	got, err := Decrypt(stored, sameDEK)
	require.NoError(t, err)
	assert.Equal(t, secretData, got)
}
