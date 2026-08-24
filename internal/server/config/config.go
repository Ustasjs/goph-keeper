// Package config loads the server settings from flags and
// environment variables. Environment variables win over flags.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	defaultAddress  = "localhost:3200"
	defaultTokenTTL = 24 * time.Hour
	defaultLogLevel = "info"
)

// Config holds all server settings.
type Config struct {
	// Address is the gRPC listen address.
	Address string
	// DatabaseDSN is the postgres connection string. Required.
	DatabaseDSN string
	// JWTSecret signs auth tokens. Required, env only.
	JWTSecret string
	// TokenTTL is the lifetime of one auth token. The session
	// lives longer: every response carries a fresh token.
	TokenTTL time.Duration
	// LogLevel is a zap level name: debug, info, warn, error.
	LogLevel string
}

// Load reads flags and environment variables and validates the
// result. It must be called once, before flag.Parse elsewhere.
func Load() (Config, error) {
	cfg := Config{
		Address:  defaultAddress,
		TokenTTL: defaultTokenTTL,
		LogLevel: defaultLogLevel,
	}

	flag.StringVar(&cfg.Address, "a", cfg.Address, "gRPC listen address")
	flag.StringVar(&cfg.DatabaseDSN, "d", cfg.DatabaseDSN, "postgres connection string")
	flag.StringVar(&cfg.LogLevel, "l", cfg.LogLevel, "log level: debug, info, warn, error")
	flag.DurationVar(&cfg.TokenTTL, "token-ttl", cfg.TokenTTL, "auth token lifetime")
	flag.Parse()

	if v := os.Getenv("ADDRESS"); v != "" {
		cfg.Address = v
	}
	if v := os.Getenv("DATABASE_DSN"); v != "" {
		cfg.DatabaseDSN = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("TOKEN_TTL"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("parse TOKEN_TTL: %w", err)
		}
		cfg.TokenTTL = ttl
	}
	cfg.JWTSecret = os.Getenv("JWT_SECRET")

	if cfg.DatabaseDSN == "" {
		return Config{}, errors.New("database DSN is required (-d flag or DATABASE_DSN)")
	}
	if cfg.JWTSecret == "" {
		return Config{}, errors.New("JWT_SECRET is required")
	}
	return cfg, nil
}
