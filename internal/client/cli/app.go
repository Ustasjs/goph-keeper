// Package cli builds the command line interface of the client.
//
// Read commands work offline: when the server does not answer,
// they show data from the local copy. Write commands need the
// server, because only the server can order concurrent changes.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	"github.com/ustasjs/goph-keeper/internal/client/payload"
	"github.com/ustasjs/goph-keeper/internal/client/remote"
	"github.com/ustasjs/goph-keeper/internal/client/store"
	"github.com/ustasjs/goph-keeper/internal/secret"
)

// Environment variables for scripts and tests. Passwords never
// come from flags: command arguments are visible to other
// processes and stay in the shell history.
const (
	envPassword       = "GOPHKEEPER_PASSWORD"
	envMasterPassword = "GOPHKEEPER_MASTER_PASSWORD"
)

// App holds what every command needs.
type App struct {
	store *store.Store
	addr  string
	// connect holds how to reach the server: TLS settings and
	// the CA file for a self-signed certificate.
	connect remote.Options
	out     io.Writer
	in      *bufio.Reader
	// tty is set when the input is a real terminal; then
	// passwords are read without echo.
	tty *os.File
	// client is built on first use, so commands that only read
	// the local copy still work with no server around.
	client *remote.Client
}

// NewApp builds the application state.
func NewApp(st *store.Store, addr string, connect remote.Options, out io.Writer, in io.Reader) *App {
	app := &App{store: st, addr: addr, connect: connect, out: out, in: bufio.NewReader(in)}
	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		app.tty = file
	}
	return app
}

// Close frees the connection, if there is one.
func (a *App) Close() error {
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// remoteClient returns the connection, building it on first use.
func (a *App) remoteClient() (*remote.Client, error) {
	if a.client != nil {
		return a.client, nil
	}

	client, err := remote.New(a.addr, a.store, a.connect)
	if err != nil {
		return nil, err
	}
	a.client = client
	return client, nil
}

// password asks for the account password.
func (a *App) password() (string, error) {
	return a.secretInput(envPassword, "Password: ")
}

// masterPassword asks for the master password. It never leaves
// this machine and is not saved anywhere.
func (a *App) masterPassword() (string, error) {
	return a.secretInput(envMasterPassword, "Master password: ")
}

// secretInput reads a hidden value, or takes it from the
// environment variable when that is set.
func (a *App) secretInput(envName, prompt string) (string, error) {
	if value, ok := os.LookupEnv(envName); ok {
		return value, nil
	}

	if a.tty != nil {
		fmt.Fprint(a.out, prompt)
		data, err := term.ReadPassword(int(a.tty.Fd()))
		fmt.Fprintln(a.out)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(data), nil
	}

	return a.line(prompt)
}

// line asks for one line of plain text.
func (a *App) line(prompt string) (string, error) {
	fmt.Fprint(a.out, prompt)

	value, err := a.in.ReadString('\n')
	if err != nil && value == "" {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimRight(value, "\r\n"), nil
}

// lineOr returns the flag value when it is set, and asks the
// user otherwise.
func (a *App) lineOr(value, prompt string) (string, error) {
	if value != "" {
		return value, nil
	}
	return a.line(prompt)
}

// dek asks for the master password and opens the data key. The
// wrapped key comes from the saved session, so reading works
// with no server.
func (a *App) dek() ([]byte, error) {
	session, err := a.store.Session()
	if err != nil {
		return nil, err
	}

	masterPassword, err := a.masterPassword()
	if err != nil {
		return nil, err
	}
	return session.UnlockDEK(masterPassword)
}

// secrets returns the records. It asks the server first and
// saves a fresh snapshot. When the server is down, it falls back
// to the local copy and says how old the data is.
func (a *App) secrets(ctx context.Context) ([]secret.Secret, error) {
	list, err := a.listFromServer(ctx)
	if err == nil {
		return list, nil
	}
	if !errors.Is(err, remote.ErrUnavailable) {
		return nil, err
	}

	cache, cacheErr := a.store.Cache()
	if cacheErr != nil {
		return nil, cacheErr
	}
	if cache.SyncedAt.IsZero() {
		return nil, fmt.Errorf("%w and there is no local copy yet", remote.ErrUnavailable)
	}

	fmt.Fprintf(a.out, "server is unavailable, showing local copy from %s\n",
		cache.SyncedAt.Format(time.RFC1123))
	return cache.Secrets, nil
}

// listFromServer reads the records and replaces the local copy.
// A full snapshot also drops the records that other clients
// deleted.
func (a *App) listFromServer(ctx context.Context) ([]secret.Secret, error) {
	client, err := a.remoteClient()
	if err != nil {
		return nil, err
	}

	list, err := client.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}

	if err := a.store.SaveCache(list, time.Now()); err != nil {
		fmt.Fprintf(a.out, "warning: cannot save the local copy: %v\n", err)
	}
	return list, nil
}

// find looks up one record by ID or by name. Names are open, so
// this needs no master password.
func find(list []secret.Secret, idOrName string) (secret.Secret, error) {
	var matches []secret.Secret
	for _, rec := range list {
		if rec.ID == idOrName {
			return rec, nil
		}
		if strings.EqualFold(rec.Name, idOrName) {
			matches = append(matches, rec)
		}
	}

	switch len(matches) {
	case 0:
		return secret.Secret{}, fmt.Errorf("%w: %s", remote.ErrNotFound, idOrName)
	case 1:
		return matches[0], nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "several records are named %q, use the id:", idOrName)
		for _, rec := range matches {
			fmt.Fprintf(&b, "\n  %s", rec.ID)
		}
		return secret.Secret{}, errors.New(b.String())
	}
}

// seal turns the content into an encrypted blob for the server.
func seal(content any, dek []byte) ([]byte, error) {
	data, err := payload.Marshal(content)
	if err != nil {
		return nil, err
	}
	return crypt.Encrypt(data, dek)
}

// open decrypts a record into its typed content.
func open(rec secret.Secret, dek []byte) (any, error) {
	data, err := crypt.Decrypt(rec.Payload, dek)
	if err != nil {
		return nil, err
	}

	content, err := payload.New(rec.Type)
	if err != nil {
		return nil, err
	}
	if err := payload.Unmarshal(data, content); err != nil {
		return nil, err
	}
	return content, nil
}
