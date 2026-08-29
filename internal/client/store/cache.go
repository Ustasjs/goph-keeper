package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ustasjs/goph-keeper/internal/secret"
)

// Cache is the last known list of records. The client replaces
// it with a full snapshot after every successful sync, so
// records deleted on another client simply disappear from it.
//
// Payloads stay encrypted here, exactly as they are on the
// server. Names and metadata are open, so listing and search
// work without the master password.
type Cache struct {
	// SyncedAt is when the snapshot was taken. Offline commands
	// show it, so the user knows how old the data is.
	SyncedAt time.Time       `json:"synced_at"`
	Secrets  []secret.Secret `json:"secrets"`
}

// Cache returns the saved snapshot. An empty cache is not an
// error: the user may have never synced on this machine.
func (s *Store) Cache() (Cache, error) {
	data, err := s.read(cacheFile)
	if err != nil {
		return Cache{}, err
	}
	if len(data) == 0 {
		return Cache{}, nil
	}

	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return Cache{}, fmt.Errorf("read cache: %w", err)
	}
	return cache, nil
}

// SaveCache replaces the snapshot with a new one.
func (s *Store) SaveCache(secrets []secret.Secret, syncedAt time.Time) error {
	data, err := json.Marshal(Cache{SyncedAt: syncedAt, Secrets: secrets})
	if err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	return s.write(cacheFile, data)
}
