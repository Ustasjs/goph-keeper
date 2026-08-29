// GophKeeper server entrypoint.
package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/ustasjs/goph-keeper/internal/logger"
	"github.com/ustasjs/goph-keeper/internal/server/auth"
	"github.com/ustasjs/goph-keeper/internal/server/config"
	"github.com/ustasjs/goph-keeper/internal/server/grpcserver"
	"github.com/ustasjs/goph-keeper/internal/server/storage/postgres"
	"github.com/ustasjs/goph-keeper/internal/server/token"
	"github.com/ustasjs/goph-keeper/migrations"
)

const shutdownTimeout = 10 * time.Second

// Build information injected at link time via
// -ldflags "-X main.buildVersion=... -X main.buildDate=...".
var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

func main() {
	fmt.Printf("Build version: %s\nBuild date: %s\n", buildVersion, buildDate)

	cfg, err := config.Load()
	if err != nil {
		stdlog.Println(err)
		os.Exit(1)
	}

	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		stdlog.Println(err)
		os.Exit(1)
	}

	if err := run(cfg, log); err != nil {
		log.Error("server terminated with error", zap.Error(err))
		_ = log.Sync()
		os.Exit(1)
	}
	_ = log.Sync()
}

func run(cfg config.Config, log *zap.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	if err := migrations.Run(cfg.DatabaseDSN); err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("create pgx pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	storage := postgres.New(pool)
	tokens := token.New([]byte(cfg.JWTSecret), cfg.TokenTTL)
	authSvc := auth.New(storage, tokens)
	server := grpcserver.New(cfg.Address, authSvc, storage, tokens, log, nil)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		log.Info("starting gRPC server", zap.String("address", cfg.Address))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, grpcserver.ErrServerStopped) {
			return err
		}
		return nil
	})

	// Wait for a shutdown signal (or a server failure), then stop
	// the server gracefully.
	g.Go(func() error {
		<-gCtx.Done()
		log.Info("shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})

	return g.Wait()
}
