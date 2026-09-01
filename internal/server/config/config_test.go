package config

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envMap turns a map into a lookup function, so a test can give
// its own environment without touching the real one.
func envMap(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

// testLoad calls load on a fresh flag set.
func testLoad(t *testing.T, args []string, env map[string]string) (Config, error) {
	t.Helper()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(nil)
	return loadFrom(fs, args, envMap(env))
}

// requiredEnv is the smallest environment that passes
// validation.
func requiredEnv() map[string]string {
	return map[string]string{
		"DATABASE_DSN": "postgres://env-dsn",
		"JWT_SECRET":   "secret",
	}
}

func TestLoad_flagWinsOverEnv(t *testing.T) {
	t.Parallel()

	env := requiredEnv()
	env["ADDRESS"] = "env-address:1000"

	// The user passed the flag by hand, so it must win.
	cfg, err := testLoad(t, []string{"-a", "flag-address:2000"}, env)
	require.NoError(t, err)
	assert.Equal(t, "flag-address:2000", cfg.Address)
}

func TestLoad_envWinsOverDefault(t *testing.T) {
	t.Parallel()

	env := requiredEnv()
	env["ADDRESS"] = "env-address:1000"
	env["LOG_LEVEL"] = "debug"
	env["TOKEN_TTL"] = "2h"

	cfg, err := testLoad(t, nil, env)
	require.NoError(t, err)
	assert.Equal(t, "env-address:1000", cfg.Address)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, 2*time.Hour, cfg.TokenTTL)
	assert.Equal(t, "postgres://env-dsn", cfg.DatabaseDSN)
}

func TestLoad_defaultsWhenNothingSet(t *testing.T) {
	t.Parallel()

	cfg, err := testLoad(t, nil, requiredEnv())
	require.NoError(t, err)
	assert.Equal(t, defaultAddress, cfg.Address)
	assert.Equal(t, defaultLogLevel, cfg.LogLevel)
	assert.Equal(t, defaultTokenTTL, cfg.TokenTTL)
}

func TestLoad_everySettingFromFlags(t *testing.T) {
	t.Parallel()

	args := []string{
		"-a", "flag-address:2000",
		"-d", "postgres://flag-dsn",
		"-l", "warn",
		"-token-ttl", "30m",
	}
	cfg, err := testLoad(t, args, map[string]string{
		"JWT_SECRET":   "secret",
		"DATABASE_DSN": "postgres://env-dsn",
		"LOG_LEVEL":    "error",
		"TOKEN_TTL":    "5h",
	})
	require.NoError(t, err)
	assert.Equal(t, "flag-address:2000", cfg.Address)
	assert.Equal(t, "postgres://flag-dsn", cfg.DatabaseDSN)
	assert.Equal(t, "warn", cfg.LogLevel)
	assert.Equal(t, 30*time.Minute, cfg.TokenTTL)
}

func TestLoad_secretComesFromEnvOnly(t *testing.T) {
	t.Parallel()

	// There is no flag for the secret, so this must fail as an
	// unknown flag, not silently set it.
	_, err := testLoad(t, []string{"-jwt-secret", "from-flag"}, requiredEnv())
	assert.Error(t, err)

	cfg, err := testLoad(t, nil, requiredEnv())
	require.NoError(t, err)
	assert.Equal(t, "secret", cfg.JWTSecret)
}

func TestLoad_missingRequired(t *testing.T) {
	t.Parallel()

	_, err := testLoad(t, nil, map[string]string{"JWT_SECRET": "secret"})
	assert.ErrorContains(t, err, "database DSN is required")

	_, err = testLoad(t, nil, map[string]string{"DATABASE_DSN": "postgres://dsn"})
	assert.ErrorContains(t, err, "JWT_SECRET is required")

	// A DSN passed by flag is enough, the environment may miss it.
	_, err = testLoad(t, []string{"-d", "postgres://flag-dsn"},
		map[string]string{"JWT_SECRET": "secret"})
	assert.NoError(t, err)
}

func TestLoad_badValues(t *testing.T) {
	t.Parallel()

	env := requiredEnv()
	env["TOKEN_TTL"] = "not a duration"
	_, err := testLoad(t, nil, env)
	assert.ErrorContains(t, err, "parse TOKEN_TTL")

	_, err = testLoad(t, []string{"-token-ttl", "0"}, requiredEnv())
	assert.ErrorContains(t, err, "must be positive")
}

func TestLoad_tlsSettings(t *testing.T) {
	t.Parallel()

	t.Run("off by default", func(t *testing.T) {
		t.Parallel()

		cfg, err := testLoad(t, nil, requiredEnv())
		require.NoError(t, err)
		assert.False(t, cfg.TLSEnabled())
	})

	t.Run("from env", func(t *testing.T) {
		t.Parallel()

		env := requiredEnv()
		env["TLS_CERT_FILE"] = "/etc/cert.pem"
		env["TLS_KEY_FILE"] = "/etc/key.pem"

		cfg, err := testLoad(t, nil, env)
		require.NoError(t, err)
		assert.True(t, cfg.TLSEnabled())
		assert.Equal(t, "/etc/cert.pem", cfg.TLSCertFile)
	})

	t.Run("flag wins over env", func(t *testing.T) {
		t.Parallel()

		env := requiredEnv()
		env["TLS_CERT_FILE"] = "/etc/env-cert.pem"
		env["TLS_KEY_FILE"] = "/etc/key.pem"

		cfg, err := testLoad(t, []string{"-tls-cert", "/tmp/flag-cert.pem"}, env)
		require.NoError(t, err)
		assert.Equal(t, "/tmp/flag-cert.pem", cfg.TLSCertFile)
		assert.Equal(t, "/etc/key.pem", cfg.TLSKeyFile)
	})

	t.Run("half a setup is an error", func(t *testing.T) {
		t.Parallel()

		// Only a certificate: the server would start without
		// encryption while the operator thinks TLS is on.
		_, err := testLoad(t, []string{"-tls-cert", "/tmp/cert.pem"}, requiredEnv())
		assert.ErrorContains(t, err, "both certificate and key")

		_, err = testLoad(t, []string{"-tls-key", "/tmp/key.pem"}, requiredEnv())
		assert.ErrorContains(t, err, "both certificate and key")
	})
}
