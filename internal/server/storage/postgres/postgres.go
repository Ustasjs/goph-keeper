// Package postgres implements the server storage on top of a
// pgx connection pool. It returns the sentinel errors declared
// by the domain packages (auth, secret).
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ustasjs/goph-keeper/internal/server/auth"
)

// Storage is the postgres implementation of the server storage.
type Storage struct {
	pool *pgxpool.Pool
}

// New builds a Storage on top of pool.
func New(pool *pgxpool.Pool) *Storage {
	return &Storage{pool: pool}
}

// CreateUser inserts an account and returns its ID. A taken
// login returns auth.ErrLoginTaken.
func (s *Storage) CreateUser(ctx context.Context, user auth.NewUser) (string, error) {
	params, err := json.Marshal(user.Crypto.KDFParams)
	if err != nil {
		return "", fmt.Errorf("marshal kdf params: %w", err)
	}

	var id string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (login, password_hash, kek_salt, kdf_params, encrypted_dek)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		user.Login, user.PasswordHash, user.Crypto.KEKSalt, params, user.Crypto.EncryptedDEK,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return "", auth.ErrLoginTaken
		}
		return "", fmt.Errorf("insert user: %w", err)
	}
	return id, nil
}

// UserByLogin returns the account with this login, or
// auth.ErrUserNotFound.
func (s *Storage) UserByLogin(ctx context.Context, login string) (auth.User, error) {
	var (
		user   auth.User
		params []byte
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, login, password_hash, kek_salt, kdf_params, encrypted_dek
		 FROM users
		 WHERE login = $1`,
		login,
	).Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Crypto.KEKSalt, &params, &user.Crypto.EncryptedDEK)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.User{}, auth.ErrUserNotFound
		}
		return auth.User{}, fmt.Errorf("select user by login: %w", err)
	}

	if err := json.Unmarshal(params, &user.Crypto.KDFParams); err != nil {
		return auth.User{}, fmt.Errorf("unmarshal kdf params: %w", err)
	}
	return user, nil
}
