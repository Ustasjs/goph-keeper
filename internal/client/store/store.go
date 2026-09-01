// Package store keeps the client state on disk: the auth token,
// the session data and the cache of records.
//
// Everything lives in one directory, by default ~/.gophkeeper.
// The directory has mode 0700 and every file 0600, so other
// users of the machine cannot read them.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	dirMode  = 0o700
	fileMode = 0o600

	tokenFile   = "token"
	sessionFile = "session.json"
	cacheFile   = "cache.json"
)

// ErrNoSession means the user is not logged in: there is no
// saved session on this machine.
var ErrNoSession = errors.New("not logged in")

// Store is the client state directory.
type Store struct {
	dir string
}

// New returns a Store in dir. An empty dir means the default
// path: $GOPHKEEPER_HOME, or ~/.gophkeeper.
func New(dir string) (*Store, error) {
	if dir == "" {
		var err error
		dir, err = defaultDir()
		if err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create store dir %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the path of the state directory.
func (s *Store) Dir() string {
	return s.dir
}

func defaultDir() (string, error) {
	if dir := os.Getenv("GOPHKEEPER_HOME"); dir != "" {
		return dir, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home dir: %w", err)
	}
	return filepath.Join(home, ".gophkeeper"), nil
}

// Token returns the saved auth token, or an empty string when
// there is none.
func (s *Store) Token() (string, error) {
	data, err := s.read(tokenFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SaveToken writes the auth token. The server sends a fresh
// token with every answer, so this runs often.
func (s *Store) SaveToken(token string) error {
	return s.write(tokenFile, []byte(token))
}

// Clear removes all files of the store. It is used by logout.
func (s *Store) Clear() error {
	var errs []error
	for _, name := range []string{tokenFile, sessionFile, cacheFile} {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// read returns the file content, or nil when the file is not
// there yet.
func (s *Store) read(name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

// write saves the file with mode 0600. It writes to a temporary
// file first and then renames it, so a crash in the middle
// cannot leave a half-written file.
func (s *Store) write(name string, data []byte) error {
	path := filepath.Join(s.dir, name)

	tmp, err := os.CreateTemp(s.dir, name+".*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file for %s: %w", name, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file for %s: %w", name, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("save %s: %w", name, err)
	}
	return nil
}
