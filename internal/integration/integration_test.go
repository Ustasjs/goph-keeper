// Package integration_test checks the whole system: the CLI
// client talks to the real server over TLS, and the server keeps
// the data in a real Postgres.
//
// Other tests cover the parts: the CLI tests run the server with
// storage in memory, and the storage tests run SQL without a
// client. Only here everything meets, so the seams are checked:
// the record type from protobuf to the database enum, the
// version counter in SQL, and the soft delete between two
// clients.
package integration_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/ustasjs/goph-keeper/internal/client/cli"
	"github.com/ustasjs/goph-keeper/internal/client/remote"
	"github.com/ustasjs/goph-keeper/internal/client/store"
	"github.com/ustasjs/goph-keeper/internal/secret"
	"github.com/ustasjs/goph-keeper/internal/server/auth"
	"github.com/ustasjs/goph-keeper/internal/server/grpcserver"
	postgresstore "github.com/ustasjs/goph-keeper/internal/server/storage/postgres"
	"github.com/ustasjs/goph-keeper/internal/server/token"
	"github.com/ustasjs/goph-keeper/internal/tlscert"
	"github.com/ustasjs/goph-keeper/migrations"
)

const (
	testPassword       = "account-password"
	testMasterPassword = "master-password"
)

// startSystem runs the server over TLS on a real port with a
// real database. Without DATABASE_DSN the test is skipped, so
// plain "go test" works with no database around.
func startSystem(t *testing.T) (addr, caFile string, pool *pgxpool.Pool) {
	t.Helper()

	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		t.Skip("DATABASE_DSN is not set")
	}
	require.NoError(t, migrations.Run(dsn))

	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	certPEM, keyPEM, err := tlscert.GeneratePEM()
	require.NoError(t, err)
	tlsConfig, err := tlscert.ServerConfig(certPEM, keyPEM)
	require.NoError(t, err)

	caFile = filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o600))

	storage := postgresstore.New(pool)
	tokens := token.New([]byte("integration-secret"), time.Hour)
	srv := grpcserver.New("", auth.New(storage, tokens), storage, tokens, zap.NewNop(), tlsConfig)

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	return lis.Addr().String(), caFile, pool
}

// client is one user's machine.
type client struct {
	t   *testing.T
	app *cli.App
	out *bytes.Buffer
}

func newClient(t *testing.T, addr, caFile string) *client {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "gophkeeper"))
	require.NoError(t, err)

	out := &bytes.Buffer{}
	app := cli.NewApp(st, addr, remote.Options{CAFile: caFile}, out, strings.NewReader(""))
	t.Cleanup(func() { _ = app.Close() })

	return &client{t: t, app: app, out: out}
}

func (c *client) run(args ...string) string {
	c.t.Helper()

	c.out.Reset()
	cmd := cli.NewRootCmd(c.app)
	cmd.SetArgs(args)
	require.NoError(c.t, cmd.Execute(), "command %v failed: %s", args, c.out.String())
	return c.out.String()
}

func setPasswords(t *testing.T) {
	t.Helper()
	t.Setenv("GOPHKEEPER_PASSWORD", testPassword)
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMasterPassword)
}

// TestSystem_everyTypeReachesTheDatabase stores one record of
// every type and reads it back. This is the path from the
// protobuf enum to the secret_type column.
func TestSystem_everyTypeReachesTheDatabase(t *testing.T) {
	setPasswords(t)
	addr, caFile, pool := startSystem(t)

	login := "user-" + uuid.New().String()
	cli := newClient(t, addr, caFile)
	cli.run("register", "--login", login)

	file := filepath.Join(t.TempDir(), "scan.pdf")
	require.NoError(t, os.WriteFile(file, []byte("file body"), 0o600))

	cli.run("add", "login-password", "--name", "github", "--login", "me")
	cli.run("add", "text", "--name", "note", "--text", "my private note")
	cli.run("add", "binary", "--name", "scan", "--file", file)
	cli.run("add", "card", "--name", "visa",
		"--number", "4111111111111111", "--holder", "ALICE", "--expiry", "12/30")

	out := cli.run("list")
	for _, name := range []string{"github", "note", "scan", "visa"} {
		assert.Contains(t, out, name)
	}

	out = cli.run("get", "note")
	assert.Contains(t, out, "my private note")

	// The database must hold the types as enum values and no
	// readable secret. Every query filters by this user: the
	// database is shared with other tests.
	var types []string
	rows, err := pool.Query(context.Background(),
		`SELECT s.type::text FROM secrets s
		 JOIN users u ON u.id = s.user_id
		 WHERE u.login = $1
		 ORDER BY s.type::text`, login)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var recordType string
		require.NoError(t, rows.Scan(&recordType))
		types = append(types, recordType)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"binary", "card", "login_password", "text"}, types)

	var payload []byte
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT s.encrypted_payload FROM secrets s
		 JOIN users u ON u.id = s.user_id
		 WHERE u.login = $1 AND s.name = 'visa'`, login).Scan(&payload))
	assert.NotContains(t, string(payload), "4111111111111111", "card number must not be stored in the open")
	assert.NotContains(t, string(payload), "ALICE")
}

// TestSystem_twoClients checks what the sync model promises:
// last write wins with a growing version, and a delete reaches
// the other client.
//
// It works through remote.Client, not the CLI: the promise
// belongs to the server, and the payload here is plain bytes,
// because the server never reads it.
func TestSystem_twoClients(t *testing.T) {
	setPasswords(t)
	addr, caFile, pool := startSystem(t)

	login := "user-" + uuid.New().String()
	owner := newClient(t, addr, caFile)
	owner.run("register", "--login", login)

	ctx := context.Background()
	first := newAPIClient(t, addr, caFile, login)
	second := newAPIClient(t, addr, caFile, login)

	id, err := first.CreateSecret(ctx, secret.NewSecret{
		Type:    secret.TypeText,
		Name:    "shared",
		Payload: []byte("original"),
	})
	require.NoError(t, err)

	// The second client sees the record of the same account.
	got, err := second.GetSecret(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), got.Payload)

	// Both clients write. Neither call fails and the later write
	// wins.
	require.NoError(t, first.UpdateSecret(ctx, secret.Update{
		ID: id, Name: "shared", Payload: []byte("from the first client"),
	}))
	require.NoError(t, second.UpdateSecret(ctx, secret.Update{
		ID: id, Name: "shared", Payload: []byte("from the second client"),
	}))

	got, err = first.GetSecret(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []byte("from the second client"), got.Payload)
	assert.Equal(t, int64(3), got.Version, "one create and two updates")

	// A delete on one client hides the record from the other.
	require.NoError(t, second.DeleteSecret(ctx, id))
	_, err = first.GetSecret(ctx, id)
	assert.ErrorIs(t, err, remote.ErrNotFound)

	// Soft delete keeps the row and only hides it, so the delete
	// can reach every client.
	var deleted bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT deleted FROM secrets WHERE id = $1`, id).Scan(&deleted))
	assert.True(t, deleted)
}

// newAPIClient logs in as an existing account and returns the
// gRPC client, so a test can call the API without the CLI.
func newAPIClient(t *testing.T, addr, caFile, login string) *remote.Client {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "gophkeeper"))
	require.NoError(t, err)

	client, err := remote.New(addr, st, remote.Options{CAFile: caFile})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Login(context.Background(), login, testPassword)
	require.NoError(t, err)
	return client
}
