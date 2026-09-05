// Package tlscert makes TLS settings for the server and the
// client.
//
// GophKeeper sends passwords and secret data over the network,
// so the connection must be encrypted. For development the
// package can generate a self-signed certificate; in production
// the operator gives real files.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// minVersion is the lowest TLS version we accept. Older
// versions have known weaknesses.
const minVersion = tls.VersionTLS12

// certValidFor is how long a generated certificate lives. It is
// short on purpose: such a certificate is for development, not
// for a real service.
const certValidFor = 365 * 24 * time.Hour

// GeneratePEM creates a private key and a self-signed
// certificate for it, PEM-encoded.
//
// The certificate is valid for the given hosts. A host can be a
// name ("localhost") or an IP address ("127.0.0.1"); the client
// checks the address it dials against this list. With no hosts
// the certificate covers localhost and the loopback addresses.
func GeneratePEM(hosts ...string) (certPEM, keyPEM []byte, err error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	// ECDSA P-256: shorter keys and faster handshakes than RSA,
	// and every modern client supports it.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper"},
			CommonName:   hosts[0],
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certValidFor),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		// The certificate signs itself, so it is its own CA.
		IsCA: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ServerConfig builds the server settings from PEM data.
func ServerConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   minVersion,
	}, nil
}

// ServerConfigFromFiles builds the server settings from files on
// disk.
func ServerConfigFromFiles(certFile, keyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair from %s and %s: %w", certFile, keyFile, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   minVersion,
	}, nil
}

// ClientConfig builds the client settings.
//
// An empty caFile means the system roots, which is right for a
// real certificate. A caFile is needed for a self-signed one:
// the client cannot trust it otherwise.
func ClientConfig(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: minVersion}
	if caFile == "" {
		return cfg, nil
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca file %s: %w", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no certificate", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// WriteFiles saves the certificate and the key. The key gets
// mode 0600: it must stay private.
func WriteFiles(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if certFile == "" || keyFile == "" {
		return errors.New("both certificate and key paths are required")
	}

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil { //nolint:gosec // the certificate is public
		return fmt.Errorf("write %s: %w", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyFile, err)
	}
	return nil
}
