package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ustasjs/goph-keeper/internal/client/remote"
	"github.com/ustasjs/goph-keeper/internal/client/store"
)

const (
	testPassword       = "account-password"
	testMasterPassword = "master-password"
)

// testCLI is one user's machine: its own state directory and its
// own connection to the server.
type testCLI struct {
	t   *testing.T
	app *App
	out *bytes.Buffer
}

func newTestCLI(t *testing.T, addr, caFile string) *testCLI {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "gophkeeper"))
	require.NoError(t, err)

	out := &bytes.Buffer{}
	// The server certificate is self-signed, so the client must
	// be told to trust it.
	connect := remote.Options{CAFile: caFile}
	app := NewApp(st, addr, connect, out, strings.NewReader(""))
	t.Cleanup(func() { _ = app.Close() })

	return &testCLI{t: t, app: app, out: out}
}

// run executes one command and returns everything it printed.
func (c *testCLI) run(args ...string) (string, error) {
	c.t.Helper()

	c.out.Reset()
	cmd := NewRootCmd(c.app)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return c.out.String(), err
}

// mustRun fails the test when the command fails.
func (c *testCLI) mustRun(args ...string) string {
	c.t.Helper()

	out, err := c.run(args...)
	require.NoError(c.t, err, "command %v failed: %s", args, out)
	return out
}

// setPasswords gives the passwords the way scripts and tests are
// meant to give them.
func setPasswords(t *testing.T) {
	t.Helper()
	t.Setenv(envPassword, testPassword)
	t.Setenv(envMasterPassword, testMasterPassword)
}

func TestCLI_registerAddGet(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)

	out := cli.mustRun("register", "--login", "alice")
	assert.Contains(t, out, "Registered as alice")

	out = cli.mustRun("add", "login-password",
		"--name", "github", "--login", "alice@example.com", "--metadata", "work")
	assert.Contains(t, out, "Added github")

	// List needs no master password: names are not encrypted.
	out = cli.mustRun("list")
	assert.Contains(t, out, "github")
	assert.Contains(t, out, "login_password")
	assert.Contains(t, out, "work")

	// Get decrypts, but hides the password by default.
	out = cli.mustRun("get", "github")
	assert.Contains(t, out, "alice@example.com")
	assert.NotContains(t, out, testPassword)

	out = cli.mustRun("get", "github", "--reveal")
	assert.Contains(t, out, testPassword)
}

func TestCLI_everyRecordType(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)
	cli.mustRun("register", "--login", "alice")

	file := filepath.Join(t.TempDir(), "scan.pdf")
	require.NoError(t, os.WriteFile(file, []byte("file body"), 0o600))

	cli.mustRun("add", "text", "--name", "note", "--text", "my private note")
	cli.mustRun("add", "binary", "--name", "scan", "--file", file)
	cli.mustRun("add", "card", "--name", "visa",
		"--number", "4111111111111111", "--holder", "ALICE", "--expiry", "12/30")

	out := cli.mustRun("get", "note")
	assert.Contains(t, out, "my private note")

	out = cli.mustRun("get", "scan")
	assert.Contains(t, out, "scan.pdf")

	out = cli.mustRun("get", "visa")
	assert.Contains(t, out, "1111", "last four digits stay visible")
	assert.NotContains(t, out, "4111111111111111")
}

func TestCLI_deleteRecord(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)
	cli.mustRun("register", "--login", "alice")
	cli.mustRun("add", "text", "--name", "note", "--text", "private")

	cli.mustRun("delete", "note")

	out := cli.mustRun("list")
	assert.Contains(t, out, "No records yet")
}

func TestCLI_secondClientSeesTheData(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)

	first := newTestCLI(t, addr, caFile)
	first.mustRun("register", "--login", "alice")
	first.mustRun("add", "text", "--name", "note", "--text", "shared secret")

	// Another machine: its own state directory, same account.
	second := newTestCLI(t, addr, caFile)
	second.mustRun("login", "--login", "alice")

	out := second.mustRun("get", "note")
	assert.Contains(t, out, "shared secret")
}

func TestCLI_wrongMasterPassword(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)
	cli.mustRun("register", "--login", "alice")
	cli.mustRun("add", "text", "--name", "note", "--text", "private")

	t.Setenv(envMasterPassword, "not the master password")

	_, err := cli.run("get", "note")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong master password")
}

func TestCLI_offlineReadsLocalCopy(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)
	cli.mustRun("register", "--login", "alice")
	cli.mustRun("add", "text", "--name", "note", "--text", "cached secret")
	// This call fills the local copy.
	cli.mustRun("list")

	// The same state directory, but the server is gone.
	offline := newTestCLI(t, "127.0.0.1:1", caFile)
	offline.app.store = cli.app.store

	out := offline.mustRun("list")
	assert.Contains(t, out, "server is unavailable")
	assert.Contains(t, out, "note")

	// Reading the content still works: the wrapped key is local.
	out = offline.mustRun("get", "note")
	assert.Contains(t, out, "cached secret")

	// Writing offline is refused.
	_, err := offline.run("add", "text", "--name", "new", "--text", "x")
	assert.Error(t, err)
}

func TestCLI_duplicateNamesNeedID(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)
	cli.mustRun("register", "--login", "alice")
	cli.mustRun("add", "text", "--name", "same", "--text", "first")
	cli.mustRun("add", "text", "--name", "same", "--text", "second")

	_, err := cli.run("get", "same")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "use the id")
}

func TestCLI_notLoggedIn(t *testing.T) {
	setPasswords(t)
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)

	_, err := cli.run("list")
	assert.Error(t, err)
}

func TestCLI_version(t *testing.T) {
	addr, caFile := startServer(t)
	cli := newTestCLI(t, addr, caFile)

	SetBuildInfo("v1.2.3", "2026-08-29")
	out := cli.mustRun("version")
	assert.Contains(t, out, "v1.2.3")
	assert.Contains(t, out, "2026-08-29")
}
