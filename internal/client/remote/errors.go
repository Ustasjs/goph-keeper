package remote

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrUnavailable means the server did not answer. Read
	// commands fall back to the cache when they see it.
	ErrUnavailable = errors.New("server is unavailable")
	// ErrUnauthenticated means the token is missing or expired.
	ErrUnauthenticated = errors.New("not logged in, run \"gophkeeper login\"")
	// ErrNotFound means there is no such record.
	ErrNotFound = errors.New("secret not found")
	// ErrLoginTaken means the login is already registered.
	ErrLoginTaken = errors.New("login is already taken")
	// ErrInvalidCredentials means a wrong login or password.
	ErrInvalidCredentials = errors.New("invalid login or password")
	// ErrTooLarge means the message did not fit the size limit.
	ErrTooLarge = errors.New("data is too large for one message")
)

// wrapError turns a gRPC status into an error the CLI can show
// and the commands can check with errors.Is. The server message
// is kept, because it explains what exactly was wrong.
func wrapError(op string, err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", op, err)
	}

	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded:
		return fmt.Errorf("%s: %w", op, ErrUnavailable)
	case codes.Unauthenticated:
		return fmt.Errorf("%s: %w", op, ErrUnauthenticated)
	case codes.NotFound:
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	case codes.AlreadyExists:
		return fmt.Errorf("%s: %w", op, ErrLoginTaken)
	case codes.ResourceExhausted:
		return fmt.Errorf("%s: %w", op, ErrTooLarge)
	case codes.InvalidArgument:
		return fmt.Errorf("%s: %s", op, st.Message())
	default:
		return fmt.Errorf("%s: %s", op, st.Message())
	}
}
