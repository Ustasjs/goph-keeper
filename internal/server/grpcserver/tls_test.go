package grpcserver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/ustasjs/goph-keeper/internal/tlscert"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// startTLSServer serves the API over TLS on a free local port
// and returns the address and the CA file the client needs.
func startTLSServer(t *testing.T) (addr, caFile string) {
	t.Helper()

	certPEM, keyPEM, err := tlscert.GeneratePEM()
	require.NoError(t, err)
	serverCfg, err := tlscert.ServerConfig(certPEM, keyPEM)
	require.NoError(t, err)

	caFile = filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o600))

	srv := New("", &fakeAuthService{}, &fakeSecretStore{}, testTokens(t), zap.NewNop(), serverCfg)

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	return lis.Addr().String(), caFile
}

func TestServer_TLS(t *testing.T) {
	t.Parallel()

	addr, caFile := startTLSServer(t)

	t.Run("client that trusts the ca works", func(t *testing.T) {
		t.Parallel()

		clientCfg, err := tlscert.ClientConfig(caFile)
		require.NoError(t, err)

		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		tokens := testTokens(t)
		tokenString, err := tokens.Generate("user-1")
		require.NoError(t, err)
		ctx := metadata.AppendToOutgoingContext(context.Background(), AuthMetadataKey, tokenString)

		client := gophkeeperv1.NewSecretsServiceClient(conn)
		_, err = client.ListSecrets(ctx, &gophkeeperv1.ListSecretsRequest{})
		assert.NoError(t, err)
	})

	t.Run("plain client is refused", func(t *testing.T) {
		t.Parallel()

		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// A client without TLS cannot reach a TLS server, so the
		// data never leaves the machine in the open.
		client := gophkeeperv1.NewSecretsServiceClient(conn)
		_, err = client.ListSecrets(ctx, &gophkeeperv1.ListSecretsRequest{})
		assert.Error(t, err)
	})
}
