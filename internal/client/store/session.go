package store

import (
	"encoding/json"
	"fmt"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
)

// Session is what the client keeps after login. The wrapped DEK
// and the KDF settings let the client decrypt records without
// asking the server again, so reading works offline.
//
// The DEK is stored wrapped, so the file is useless without the
// master password.
type Session struct {
	Login        string          `json:"login"`
	KEKSalt      []byte          `json:"kek_salt"`
	KDFParams    crypt.KDFParams `json:"kdf_params"`
	EncryptedDEK []byte          `json:"encrypted_dek"`
}

// Session returns the saved session. It returns ErrNoSession
// when the user has not logged in on this machine.
func (s *Store) Session() (Session, error) {
	data, err := s.read(sessionFile)
	if err != nil {
		return Session{}, err
	}
	if len(data) == 0 {
		return Session{}, ErrNoSession
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}
	return session, nil
}

// SaveSession writes the session after register or login.
func (s *Store) SaveSession(session Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return s.write(sessionFile, data)
}

// UnlockDEK turns the master password into the data key. A wrong
// password returns crypt.ErrWrongMasterPassword, because the
// wrapped DEK does not decrypt.
func (s Session) UnlockDEK(masterPassword string) ([]byte, error) {
	kek, err := crypt.DeriveKEK(masterPassword, s.KEKSalt, s.KDFParams)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return crypt.UnwrapDEK(s.EncryptedDEK, kek)
}
