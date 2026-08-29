// Package secret owns the stored record entity. The payload is
// an encrypted blob the server cannot read; the name and the
// metadata are plain text.
package secret

import (
	"errors"
	"time"
)

// ErrNotFound means the user has no live record with this ID.
var ErrNotFound = errors.New("secret not found")

// Type says what kind of data is inside the payload. The values
// match the secret_type enum in the database.
type Type string

// The known record types.
const (
	TypeLoginPassword Type = "login_password"
	TypeText          Type = "text"
	TypeBinary        Type = "binary"
	TypeCard          Type = "card"
)

// Valid reports whether t is one of the known types.
func (t Type) Valid() bool {
	switch t {
	case TypeLoginPassword, TypeText, TypeBinary, TypeCard:
		return true
	}
	return false
}

// Secret is one stored record.
type Secret struct {
	ID        string
	Type      Type
	Name      string
	Metadata  string
	Payload   []byte
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewSecret is the data needed to create a record.
type NewSecret struct {
	Type     Type
	Name     string
	Metadata string
	Payload  []byte
}

// Update is the data to replace in an existing record.
type Update struct {
	ID       string
	Name     string
	Metadata string
	Payload  []byte
}
