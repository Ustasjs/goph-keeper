// Certgen makes a self-signed certificate for local work.
//
// The server needs a certificate to serve over TLS, and the
// client needs the same certificate to trust it. For a real
// service use a certificate from a certificate authority
// instead.
package main

import (
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"strings"

	"github.com/ustasjs/goph-keeper/internal/tlscert"
)

func main() {
	certFile := flag.String("cert", "cert.pem", "where to write the certificate")
	keyFile := flag.String("key", "key.pem", "where to write the private key")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1",
		"comma separated names and addresses the certificate is valid for")
	flag.Parse()

	if err := run(*certFile, *keyFile, *hosts); err != nil {
		stdlog.Println(err)
		os.Exit(1)
	}
}

func run(certFile, keyFile, hosts string) error {
	certPEM, keyPEM, err := tlscert.GeneratePEM(strings.Split(hosts, ",")...)
	if err != nil {
		return err
	}
	if err := tlscert.WriteFiles(certFile, keyFile, certPEM, keyPEM); err != nil {
		return err
	}

	fmt.Printf("Certificate: %s\nPrivate key: %s\nValid for:   %s\n", certFile, keyFile, hosts)
	return nil
}
