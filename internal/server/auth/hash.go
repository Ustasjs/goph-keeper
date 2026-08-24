package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Server-side Argon2id settings for the account password hash.
const (
	hashMemoryKiB = 19 * 1024
	hashTime      = 2
	hashThreads   = 1
	hashSaltLen   = 16
	hashKeyLen    = 32
)

var errMalformedHash = errors.New("malformed password hash")

// hashPassword returns the Argon2id hash of password in the PHC
// string format: $argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>.
func hashPassword(password string) (string, error) {
	salt := make([]byte, hashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, hashTime, hashMemoryKiB, hashThreads, hashKeyLen)

	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, hashMemoryKiB, hashTime, hashThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// verifyPassword checks password against a PHC-format hash. It
// uses the params stored in the hash, not the current constants,
// so old hashes keep working after the constants change.
func verifyPassword(phc, password string) (bool, error) {
	parts := strings.Split(phc, "$")
	// Empty first part: the string starts with "$".
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, errMalformedHash
	}
	if version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version %d", version)
	}

	var memoryKiB, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &timeCost, &threads); err != nil {
		return false, errMalformedHash
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errMalformedHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, errMalformedHash
	}

	got := argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
