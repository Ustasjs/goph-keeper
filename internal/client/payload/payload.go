// Package payload holds the secret content of a record.
//
// The content is encrypted on the client, so only the client
// knows its shape. The server sees a blob of bytes and the open
// name and metadata of the record.
package payload

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ustasjs/goph-keeper/internal/secret"
)

// MaxSize is the biggest payload the client sends. The gRPC
// message limit is 4 MB, and the payload is the largest part of
// a message, so the check happens before encryption to give a
// clear error.
const MaxSize = 4 << 20

// ErrTooLarge means the data does not fit the message limit.
var ErrTooLarge = errors.New("data is too large")

// LoginPassword is a login and password pair.
type LoginPassword struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Text is any text the user wants to keep.
type Text struct {
	Text string `json:"text"`
}

// Binary is any file.
type Binary struct {
	// Filename is the original name, kept to save the file back.
	Filename string `json:"filename"`
	Data     []byte `json:"data"`
}

// Card is a bank card.
type Card struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	// Expiry is in MM/YY form.
	Expiry string `json:"expiry"`
	CVV    string `json:"cvv"`
}

// Marshal turns the content into JSON, ready to be encrypted.
// It returns ErrTooLarge when the result does not fit the
// message limit.
func Marshal(content any) ([]byte, error) {
	data, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%w: %d bytes, limit is %d", ErrTooLarge, len(data), MaxSize)
	}
	return data, nil
}

// Unmarshal reads the content of a known type from decrypted
// JSON. Pass a pointer to the type that matches the record.
func Unmarshal(data []byte, content any) error {
	if err := json.Unmarshal(data, content); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	return nil
}

// New returns an empty content value for a record type, ready
// for Unmarshal.
func New(recordType secret.Type) (any, error) {
	switch recordType {
	case secret.TypeLoginPassword:
		return &LoginPassword{}, nil
	case secret.TypeText:
		return &Text{}, nil
	case secret.TypeBinary:
		return &Binary{}, nil
	case secret.TypeCard:
		return &Card{}, nil
	default:
		return nil, fmt.Errorf("unknown secret type %q", recordType)
	}
}
