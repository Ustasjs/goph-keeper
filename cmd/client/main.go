// GophKeeper CLI client.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ustasjs/goph-keeper/internal/client/cli"
	"github.com/ustasjs/goph-keeper/internal/client/remote"
	"github.com/ustasjs/goph-keeper/internal/client/store"
)

const defaultAddress = "localhost:3200"

// Build information injected at link time via
// -ldflags "-X main.buildVersion=... -X main.buildDate=...".
var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	cli.SetBuildInfo(buildVersion, buildDate)

	// Ctrl+C stops a slow call instead of leaving the terminal
	// stuck.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.New(os.Getenv("GOPHKEEPER_HOME"))
	if err != nil {
		return err
	}

	addr := os.Getenv("GOPHKEEPER_ADDRESS")
	if addr == "" {
		addr = defaultAddress
	}

	// TLS is on by default. GOPHKEEPER_CA_FILE points to the
	// server certificate when it is self-signed;
	// GOPHKEEPER_INSECURE=1 turns encryption off for local work.
	connect := remote.Options{
		CAFile:   os.Getenv("GOPHKEEPER_CA_FILE"),
		Insecure: os.Getenv("GOPHKEEPER_INSECURE") == "1",
	}

	app := cli.NewApp(st, addr, connect, os.Stdout, os.Stdin)
	defer func() { _ = app.Close() }()

	return cli.NewRootCmd(app).ExecuteContext(ctx)
}
