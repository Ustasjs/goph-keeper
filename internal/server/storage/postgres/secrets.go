package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ustasjs/goph-keeper/internal/server/secret"
)

// The queries filter with "deleted = false" written exactly like
// the predicate of the partial index secrets_user_id_live_idx.

// CreateSecret inserts a record and returns its ID and version.
func (s *Storage) CreateSecret(ctx context.Context, userID string, ns secret.NewSecret) (secret.Secret, error) {
	var created secret.Secret
	err := s.pool.QueryRow(ctx,
		`INSERT INTO secrets (user_id, type, name, metadata, encrypted_payload)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, version`,
		userID, string(ns.Type), ns.Name, ns.Metadata, ns.Payload,
	).Scan(&created.ID, &created.Version)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("insert secret: %w", err)
	}
	return created, nil
}

// SecretByID returns one live record of the user, or
// secret.ErrNotFound.
func (s *Storage) SecretByID(ctx context.Context, userID, id string) (secret.Secret, error) {
	var (
		rec     secret.Secret
		rawType string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, type, name, metadata, encrypted_payload, version, created_at, updated_at
		 FROM secrets
		 WHERE id = $1 AND user_id = $2 AND deleted = false`,
		id, userID,
	).Scan(&rec.ID, &rawType, &rec.Name, &rec.Metadata, &rec.Payload, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return secret.Secret{}, secret.ErrNotFound
		}
		return secret.Secret{}, fmt.Errorf("select secret: %w", err)
	}

	rec.Type = secret.Type(rawType)
	return rec, nil
}

// ListSecrets returns all live records of the user, newest
// updates first.
func (s *Storage) ListSecrets(ctx context.Context, userID string) ([]secret.Secret, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, type, name, metadata, encrypted_payload, version, created_at, updated_at
		 FROM secrets
		 WHERE user_id = $1 AND deleted = false
		 ORDER BY updated_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("select secrets: %w", err)
	}
	defer rows.Close()

	var list []secret.Secret
	for rows.Next() {
		var (
			rec     secret.Secret
			rawType string
		)
		err := rows.Scan(&rec.ID, &rawType, &rec.Name, &rec.Metadata, &rec.Payload,
			&rec.Version, &rec.CreatedAt, &rec.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		rec.Type = secret.Type(rawType)
		list = append(list, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secrets: %w", err)
	}
	return list, nil
}

// UpdateSecret replaces the name, the metadata and the payload
// of a live record and returns the new version. Last write wins:
// there is no version check, the update just bumps it.
func (s *Storage) UpdateSecret(ctx context.Context, userID string, upd secret.Update) (int64, error) {
	var version int64
	err := s.pool.QueryRow(ctx,
		`UPDATE secrets
		 SET name = $1, metadata = $2, encrypted_payload = $3,
		     version = version + 1, updated_at = now()
		 WHERE id = $4 AND user_id = $5 AND deleted = false
		 RETURNING version`,
		upd.Name, upd.Metadata, upd.Payload, upd.ID, userID,
	).Scan(&version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, secret.ErrNotFound
		}
		return 0, fmt.Errorf("update secret: %w", err)
	}
	return version, nil
}

// DeleteSecret marks a live record as deleted (soft delete).
func (s *Storage) DeleteSecret(ctx context.Context, userID, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE secrets
		 SET deleted = true, version = version + 1, updated_at = now()
		 WHERE id = $1 AND user_id = $2 AND deleted = false`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return secret.ErrNotFound
	}
	return nil
}
