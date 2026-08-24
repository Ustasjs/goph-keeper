// Package auth registers users and logs them in. It owns the
// user entity and the account password hashing.
package auth

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrLoginTaken means the login is already registered.
	ErrLoginTaken = errors.New("login is taken")
	// ErrInvalidCredentials means unknown login or wrong password.
	// One error for both cases, so the answer does not tell an
	// attacker which part was wrong.
	ErrInvalidCredentials = errors.New("invalid login or password")
	// ErrUserNotFound means there is no user with this login.
	ErrUserNotFound = errors.New("user not found")
)

// KDFParams are the client-side Argon2id settings. The server
// stores them as-is and returns them at login.
type KDFParams struct {
	MemoryKiB uint32 `json:"memory_kib"`
	Time      uint32 `json:"time"`
	Threads   uint32 `json:"threads"`
}

// CryptoBundle is the client-side encryption material: the KEK
// salt, the KDF params and the wrapped DEK. The server cannot
// use it, only store it.
type CryptoBundle struct {
	KEKSalt      []byte
	KDFParams    KDFParams
	EncryptedDEK []byte
}

// User is one stored account.
type User struct {
	ID           string
	Login        string
	PasswordHash string
	Crypto       CryptoBundle
}

// NewUser is the data needed to create an account.
type NewUser struct {
	Login        string
	PasswordHash string
	Crypto       CryptoBundle
}

// userRepo is the storage this service needs.
type userRepo interface {
	// CreateUser returns the new user ID. It returns
	// ErrLoginTaken when the login is already registered.
	CreateUser(ctx context.Context, user NewUser) (string, error)
	// UserByLogin returns ErrUserNotFound when there is no such
	// login.
	UserByLogin(ctx context.Context, login string) (User, error)
}

// tokenIssuer makes auth tokens for logged-in users.
type tokenIssuer interface {
	Generate(userID string) (string, error)
}

// Service is the auth use case.
type Service struct {
	users  userRepo
	tokens tokenIssuer
}

// New builds a Service.
func New(users userRepo, tokens tokenIssuer) *Service {
	return &Service{users: users, tokens: tokens}
}

// Register creates an account and returns an auth token, so the
// new user is logged in at once.
func (s *Service) Register(ctx context.Context, login, password string, crypto CryptoBundle) (string, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	userID, err := s.users.CreateUser(ctx, NewUser{
		Login:        login,
		PasswordHash: hash,
		Crypto:       crypto,
	})
	if err != nil {
		return "", fmt.Errorf("create user %s: %w", login, err)
	}

	authToken, err := s.tokens.Generate(userID)
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return authToken, nil
}

// Login checks the account password. It returns an auth token
// and the stored crypto material, so the client can unwrap the
// DEK locally.
func (s *Service) Login(ctx context.Context, login, password string) (string, CryptoBundle, error) {
	user, err := s.users.UserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", CryptoBundle{}, ErrInvalidCredentials
		}
		return "", CryptoBundle{}, fmt.Errorf("find user %s: %w", login, err)
	}

	ok, err := verifyPassword(user.PasswordHash, password)
	if err != nil {
		return "", CryptoBundle{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return "", CryptoBundle{}, ErrInvalidCredentials
	}

	authToken, err := s.tokens.Generate(user.ID)
	if err != nil {
		return "", CryptoBundle{}, fmt.Errorf("generate token: %w", err)
	}
	return authToken, user.Crypto, nil
}
