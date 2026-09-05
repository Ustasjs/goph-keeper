package remote

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/ustasjs/goph-keeper/internal/tlscert"
)

func TestTransportCredentials_tlsByDefault(t *testing.T) {
	t.Parallel()

	// An empty Options must still mean TLS: encryption is not
	// something the user has to remember to turn on.
	creds, err := transportCredentials(Options{})
	require.NoError(t, err)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
}

func TestTransportCredentials_withCAFile(t *testing.T) {
	t.Parallel()

	certPEM, _, err := tlscert.GeneratePEM()
	require.NoError(t, err)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o600))

	creds, err := transportCredentials(Options{CAFile: caFile})
	require.NoError(t, err)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
}

func TestTransportCredentials_badCAFile(t *testing.T) {
	t.Parallel()

	_, err := transportCredentials(Options{CAFile: "no-such-file"})
	assert.Error(t, err)
}

func TestTransportCredentials_insecure(t *testing.T) {
	t.Parallel()

	creds, err := transportCredentials(Options{Insecure: true})
	require.NoError(t, err)
	assert.Equal(t, insecure.NewCredentials().Info().SecurityProtocol, creds.Info().SecurityProtocol)
}

func TestNew_badCAFileFailsEarly(t *testing.T) {
	t.Parallel()

	// A wrong CA path must be reported at once, not on the first
	// call.
	_, err := New("localhost:3200", &memoryTokenStore{}, Options{CAFile: "no-such-file"})
	assert.ErrorContains(t, err, "no-such-file")
}

func TestWrapError_tlsProblemVsServerDown(t *testing.T) {
	t.Parallel()

	// Both cases arrive as Unavailable, but they need different
	// fixes, so the client must tell them apart.
	tlsErr := wrapError("list secrets", status.Error(codes.Unavailable,
		`transport: authentication handshake failed: tls: failed to verify certificate: `+
			`x509: certificate signed by unknown authority`))
	assert.ErrorIs(t, tlsErr, ErrUntrustedServer)
	assert.NotErrorIs(t, tlsErr, ErrUnavailable)
	assert.Contains(t, tlsErr.Error(), "GOPHKEEPER_CA_FILE")

	downErr := wrapError("list secrets", status.Error(codes.Unavailable,
		"connection refused"))
	assert.ErrorIs(t, downErr, ErrUnavailable)
	assert.NotErrorIs(t, downErr, ErrUntrustedServer)
}
