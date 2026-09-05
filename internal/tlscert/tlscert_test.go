package tlscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePEM_defaultHosts(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := GeneratePEM()
	require.NoError(t, err)
	assert.Contains(t, string(certPEM), "BEGIN CERTIFICATE")
	assert.Contains(t, string(keyPEM), "BEGIN EC PRIVATE KEY")

	cert := parseCert(t, certPEM)
	assert.Contains(t, cert.DNSNames, "localhost")
	assert.True(t, cert.IsCA)
	assert.True(t, cert.NotAfter.After(time.Now()), "certificate must not be expired")

	// The client dials 127.0.0.1 in tests, so that address must
	// be covered too.
	assert.NoError(t, cert.VerifyHostname("127.0.0.1"))
	assert.NoError(t, cert.VerifyHostname("localhost"))
}

func TestGeneratePEM_customHosts(t *testing.T) {
	t.Parallel()

	certPEM, _, err := GeneratePEM("keeper.example.com", "10.0.0.7")
	require.NoError(t, err)

	cert := parseCert(t, certPEM)
	assert.Equal(t, []string{"keeper.example.com"}, cert.DNSNames)
	require.Len(t, cert.IPAddresses, 1)
	assert.Equal(t, "10.0.0.7", cert.IPAddresses[0].String())

	// A host outside the list must be refused.
	assert.Error(t, cert.VerifyHostname("other.example.com"))
}

func TestGeneratePEM_uniqueEveryTime(t *testing.T) {
	t.Parallel()

	first, _, err := GeneratePEM()
	require.NoError(t, err)
	second, _, err := GeneratePEM()
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "each certificate needs its own serial and key")
}

func TestServerConfig_setsMinVersion(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := GeneratePEM()
	require.NoError(t, err)

	cfg, err := ServerConfig(certPEM, keyPEM)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	require.Len(t, cfg.Certificates, 1)
}

func TestServerConfig_brokenPEM(t *testing.T) {
	t.Parallel()

	_, err := ServerConfig([]byte("not a certificate"), []byte("not a key"))
	assert.Error(t, err)
}

func TestServerConfigFromFiles(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTestCert(t)

	cfg, err := ServerConfigFromFiles(certFile, keyFile)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)

	_, err = ServerConfigFromFiles("no-such-file", keyFile)
	assert.Error(t, err)
}

func TestClientConfig(t *testing.T) {
	t.Parallel()

	t.Run("system roots when no ca given", func(t *testing.T) {
		t.Parallel()

		cfg, err := ClientConfig("")
		require.NoError(t, err)
		assert.Nil(t, cfg.RootCAs, "no CA file means the system roots")
		assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	})

	t.Run("trusts the given ca", func(t *testing.T) {
		t.Parallel()

		certFile, _ := writeTestCert(t)

		cfg, err := ClientConfig(certFile)
		require.NoError(t, err)
		assert.NotNil(t, cfg.RootCAs)
	})

	t.Run("bad ca file", func(t *testing.T) {
		t.Parallel()

		_, err := ClientConfig("no-such-file")
		assert.Error(t, err)

		empty := filepath.Join(t.TempDir(), "empty.pem")
		require.NoError(t, os.WriteFile(empty, []byte("not a pem"), 0o600))
		_, err = ClientConfig(empty)
		assert.ErrorContains(t, err, "no certificate")
	})
}

func TestWriteFiles_keyIsPrivate(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := GeneratePEM()
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, WriteFiles(certFile, keyFile, certPEM, keyPEM))

	keyInfo, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm(), "the key must stay private")

	certInfo, err := os.Stat(certFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm(), "the certificate is public")

	assert.Error(t, WriteFiles("", keyFile, certPEM, keyPEM))
}

// TestHandshake proves the pieces work together: a server with
// our config and a client that trusts our CA can talk, and a
// client without that CA cannot.
func TestHandshake(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := GeneratePEM()
	require.NoError(t, err)
	serverCfg, err := ServerConfig(certPEM, keyPEM)
	require.NoError(t, err)

	var lc net.ListenConfig
	rawListener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := tls.NewListener(rawListener, serverCfg)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
		}
	}()

	addr := rawListener.Addr().String()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o600))

	t.Run("trusted client connects", func(t *testing.T) {
		clientCfg, err := ClientConfig(caFile)
		require.NoError(t, err)

		dialer := tls.Dialer{Config: clientCfg}
		conn, err := dialer.DialContext(context.Background(), "tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		tlsConn, ok := conn.(*tls.Conn)
		require.True(t, ok)
		assert.GreaterOrEqual(t, tlsConn.ConnectionState().Version, uint16(tls.VersionTLS12))

		buf := make([]byte, 5)
		_, err = conn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(buf))
	})

	t.Run("client without the ca is refused", func(t *testing.T) {
		clientCfg, err := ClientConfig("")
		require.NoError(t, err)

		// A self-signed certificate is unknown to the system
		// roots, so the handshake must fail.
		dialer := tls.Dialer{Config: clientCfg}
		_, err = dialer.DialContext(context.Background(), "tcp", addr)
		require.Error(t, err)
		var unknownAuthority x509.UnknownAuthorityError
		assert.ErrorAs(t, err, &unknownAuthority)
	})
}

// parseCert reads the certificate back, so a test can check
// what went into it.
func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "certificate must be valid PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	certPEM, keyPEM, err := GeneratePEM()
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, WriteFiles(certFile, keyFile, certPEM, keyPEM))
	return certFile, keyFile
}
