// Package crypt holds all client-side cryptography.
//
// The scheme has two keys. The DEK (data encryption key) is a
// random key that encrypts the secret data. The KEK (key
// encryption key) comes from the master password and encrypts
// the DEK itself. The server stores only the wrapped DEK, so it
// can never read the data.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// KeyLen is the size of both the KEK and the DEK: 32 bytes
	// for AES-256.
	KeyLen = 32
	// SaltLen is the size of the KEK salt.
	SaltLen = 16
)

// Default Argon2id settings for a new user. They are sent to the
// server at register time and come back at login, so they can
// grow later without breaking old accounts.
const (
	DefaultMemoryKiB = 64 * 1024
	DefaultTime      = 1
	DefaultThreads   = 4
)

var (
	// ErrWrongMasterPassword means the DEK did not decrypt. The
	// master password is wrong, or the stored data is broken.
	ErrWrongMasterPassword = errors.New("wrong master password")
	// ErrBadCiphertext means the data is not valid or was
	// changed after encryption.
	ErrBadCiphertext = errors.New("cannot decrypt data")
	// ErrBadKey means the key has a wrong size.
	ErrBadKey = errors.New("key must be 32 bytes")
)

// KDFParams are the Argon2id settings used to build the KEK.
type KDFParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultKDFParams returns the settings for a new user.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		MemoryKiB: DefaultMemoryKiB,
		Time:      DefaultTime,
		Threads:   DefaultThreads,
	}
}

// Valid reports whether the params can be used. Values come from
// the server, so they are checked before use: argon2 panics on a
// zero time or threads.
func (p KDFParams) Valid() bool {
	return p.MemoryKiB > 0 && p.Time > 0 && p.Threads > 0
}

// NewSalt returns a random salt for the KEK.
func NewSalt() ([]byte, error) {
	return randomBytes(SaltLen)
}

// NewDEK returns a new random data encryption key.
func NewDEK() ([]byte, error) {
	return randomBytes(KeyLen)
}

// DeriveKEK builds the key encryption key from the master
// password. The same password, salt and params always give the
// same key.
func DeriveKEK(masterPassword string, salt []byte, params KDFParams) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt is empty")
	}
	if !params.Valid() {
		return nil, fmt.Errorf("bad kdf params: %+v", params)
	}

	return argon2.IDKey([]byte(masterPassword), salt,
		params.Time, params.MemoryKiB, params.Threads, KeyLen), nil
}

// WrapDEK encrypts the DEK with the KEK.
func WrapDEK(dek, kek []byte) ([]byte, error) {
	return Encrypt(dek, kek)
}

// UnwrapDEK decrypts the DEK with the KEK. A failure here means
// the master password is wrong: the GCM tag does not match.
func UnwrapDEK(wrapped, kek []byte) ([]byte, error) {
	dek, err := Decrypt(wrapped, kek)
	if err != nil {
		if errors.Is(err, ErrBadCiphertext) {
			return nil, ErrWrongMasterPassword
		}
		return nil, err
	}
	return dek, nil
}

// Encrypt encrypts plaintext with AES-256-GCM. The result is
// nonce + ciphertext + tag. Every call uses a new random nonce.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Seal appends the result to the nonce, so the nonce becomes
	// the first bytes of the output.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data made by Encrypt. It returns
// ErrBadCiphertext when the key is wrong or the data was
// changed.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrBadCiphertext
	}

	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrBadCiphertext
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}
