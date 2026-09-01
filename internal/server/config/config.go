// Package config loads the server settings.
//
// Values come from three places. Defaults are the base,
// environment variables override them, and command line flags
// win over everything: the environment describes where the
// server runs (container, CI), while a flag is a one-time
// override made by hand.
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
	// JWTSecret signs auth tokens. Required.
	JWTSecret string
	// TokenTTL is the lifetime of one auth token. The session
	// lives longer: every answer carries a fresh token.
	TokenTTL time.Duration
	// LogLevel is a zap level name: debug, info, warn, error.
	LogLevel string
}

// Load reads the settings for the running program. It must be
// called once, because it parses the command line.
func Load() (Config, error) {
	return loadFrom(flag.CommandLine, os.Args[1:], os.LookupEnv)
}

// loadFrom does the work on a given flag set, so tests can call it
// many times with their own arguments and environment.
func loadFrom(fs *flag.FlagSet, args []string, lookupEnv func(string) (string, bool)) (Config, error) {
	cfg := Config{
		Address:  defaultAddress,
		TokenTTL: defaultTokenTTL,
		LogLevel: defaultLogLevel,
	}

	// Step one: the environment replaces the defaults.
	if err := applyEnv(&cfg, lookupEnv); err != nil {
		return Config{}, err
	}

	// Step two: the flags start from those values, so a flag
	// that the user passed wins, and a flag left out keeps what
	// the environment said.
	fs.StringVar(&cfg.Address, "a", cfg.Address, "gRPC listen address")
	fs.StringVar(&cfg.DatabaseDSN, "d", cfg.DatabaseDSN, "postgres connection string")
	fs.StringVar(&cfg.LogLevel, "l", cfg.LogLevel, "log level: debug, info, warn, error")
	fs.DurationVar(&cfg.TokenTTL, "token-ttl", cfg.TokenTTL, "auth token lifetime")
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse flags: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config, lookupEnv func(string) (string, bool)) error {
	if v, ok := lookupEnv("ADDRESS"); ok && v != "" {
		cfg.Address = v
	}
	if v, ok := lookupEnv("DATABASE_DSN"); ok && v != "" {
		cfg.DatabaseDSN = v
	}
	if v, ok := lookupEnv("LOG_LEVEL"); ok && v != "" {
		cfg.LogLevel = v
	}
	if v, ok := lookupEnv("JWT_SECRET"); ok {
		cfg.JWTSecret = v
	}
	if v, ok := lookupEnv("TOKEN_TTL"); ok && v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parse TOKEN_TTL: %w", err)
		}
		cfg.TokenTTL = ttl
	}
	return nil
}

func (c Config) validate() error {
	if c.DatabaseDSN == "" {
		return errors.New("database DSN is required (-d flag or DATABASE_DSN)")
	}
	if c.JWTSecret == "" {
		return errors.New("JWT_SECRET is required")
	}
	if c.TokenTTL <= 0 {
		return fmt.Errorf("token lifetime must be positive, got %s", c.TokenTTL)
	}
	return nil
}
