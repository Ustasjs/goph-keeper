// Package grpcserver serves the GophKeeper API over gRPC. The
// RPC handlers are thin: they validate input, call the domain
// packages and map their errors to gRPC status codes.
package grpcserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ustasjs/goph-keeper/internal/secret"
	"github.com/ustasjs/goph-keeper/internal/server/auth"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// ErrServerStopped is what ListenAndServe returns after Stop,
// the gRPC twin of http.ErrServerClosed.
var ErrServerStopped = grpc.ErrServerStopped

// AuthService is the auth use case behind the AuthService RPCs.
// *auth.Service implements it.
type AuthService interface {
	Register(ctx context.Context, login, password string, crypto auth.CryptoBundle) (string, error)
	Login(ctx context.Context, login, password string) (string, auth.CryptoBundle, error)
}

// SecretStore is the storage behind the SecretsService RPCs.
// *postgres.Storage implements it.
type SecretStore interface {
	CreateSecret(ctx context.Context, userID string, ns secret.NewSecret) (secret.Secret, error)
	SecretByID(ctx context.Context, userID, id string) (secret.Secret, error)
	ListSecrets(ctx context.Context, userID string) ([]secret.Secret, error)
	UpdateSecret(ctx context.Context, userID string, upd secret.Update) (int64, error)
	DeleteSecret(ctx context.Context, userID, id string) error
}

// TokenService checks incoming tokens and issues fresh ones for
// the sliding session. *token.Service implements it.
type TokenService interface {
	ParseUserID(tokenString string) (string, error)
	Generate(userID string) (string, error)
}

// Server runs the GophKeeper services on addr. Its API copies
// *http.Server, so main can start and stop it the usual way.
type Server struct {
	grpc *grpc.Server
	addr string
}

// New builds a Server. tlsConfig may be nil, and then the server
// speaks plain HTTP/2 (dev only; TLS arrives in its own stage).
func New(addr string, authSvc AuthService, secrets SecretStore, tokens TokenService, log *zap.Logger, tlsConfig *tls.Config) *Server {
	// Recovery comes first, so it also covers a panic in the
	// other interceptors. Logging comes next, so requests
	// rejected by auth are logged too.
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			recoveryInterceptor(log),
			loggingInterceptor(log),
			authInterceptor(tokens, log),
		),
	}
	if tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	srv := grpc.NewServer(opts...)
	gophkeeperv1.RegisterAuthServiceServer(srv, &authServer{auth: authSvc, log: log})
	gophkeeperv1.RegisterSecretsServiceServer(srv, &secretsServer{secrets: secrets, log: log})

	return &Server{grpc: srv, addr: addr}
}

// Serve serves on lis and blocks until the server stops. Tests
// use it to serve over an in-memory listener.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpc.Serve(lis)
}

// ListenAndServe listens on the configured address and blocks
// until the server stops.
func (s *Server) ListenAndServe() error {
	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc listen on %s: %w", s.addr, err)
	}
	return s.Serve(lis)
}

// Shutdown stops the server after the running calls finish. If
// ctx runs out first, it kills the remaining connections and
// returns the ctx error.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.grpc.Stop()
		return ctx.Err()
	}
}
