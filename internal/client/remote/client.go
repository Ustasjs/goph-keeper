// Package remote talks to the GophKeeper server over gRPC.
//
// It hides the generated code from the rest of the client: the
// methods take and return plain Go types, and gRPC status codes
// become the errors declared in this package.
package remote

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// TokenStore keeps the auth token between runs. *store.Store
// implements it.
type TokenStore interface {
	Token() (string, error)
	SaveToken(token string) error
}

// CryptoBundle is the client-side encryption material that the
// server stores but cannot use.
type CryptoBundle struct {
	KEKSalt      []byte
	KDFParams    crypt.KDFParams
	EncryptedDEK []byte
}

// Client is a connection to the server.
type Client struct {
	conn    *grpc.ClientConn
	auth    gophkeeperv1.AuthServiceClient
	secrets gophkeeperv1.SecretsServiceClient
	tokens  TokenStore
}

// New connects to the server at addr. The interceptor sends the
// saved token with every call and saves the fresh token from
// every answer, which keeps the session alive.
//
// The connection is not encrypted yet; TLS comes in its own
// stage.
func New(addr string, tokens TokenStore) (*Client, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(tokenInterceptor(tokens)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}

	return &Client{
		conn:    conn,
		auth:    gophkeeperv1.NewAuthServiceClient(conn),
		secrets: gophkeeperv1.NewSecretsServiceClient(conn),
		tokens:  tokens,
	}, nil
}

// Close ends the connection.
func (c *Client) Close() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("close connection: %w", err)
	}
	return nil
}

// Register creates an account and saves the token. The crypto
// material comes from the caller: the server only stores it.
func (c *Client) Register(ctx context.Context, login, password string, bundle CryptoBundle) error {
	req := gophkeeperv1.RegisterRequest_builder{
		Login:        proto.String(login),
		Password:     proto.String(password),
		KekSalt:      bundle.KEKSalt,
		KdfParams:    kdfParamsToProto(bundle.KDFParams),
		EncryptedDek: bundle.EncryptedDEK,
	}.Build()

	resp, err := c.auth.Register(ctx, req)
	if err != nil {
		return wrapError("register", err)
	}

	if err := c.tokens.SaveToken(resp.GetToken()); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	return nil
}

// Login checks the account password and returns the crypto
// material, so the client can unwrap the DEK with the master
// password.
func (c *Client) Login(ctx context.Context, login, password string) (CryptoBundle, error) {
	req := gophkeeperv1.LoginRequest_builder{
		Login:    proto.String(login),
		Password: proto.String(password),
	}.Build()

	resp, err := c.auth.Login(ctx, req)
	if err != nil {
		wrapped := wrapError("login", err)
		// For this call Unauthenticated means wrong login or
		// password, not an expired session.
		if errors.Is(wrapped, ErrUnauthenticated) {
			return CryptoBundle{}, fmt.Errorf("login: %w", ErrInvalidCredentials)
		}
		return CryptoBundle{}, wrapped
	}

	if err := c.tokens.SaveToken(resp.GetToken()); err != nil {
		return CryptoBundle{}, fmt.Errorf("save token: %w", err)
	}

	return CryptoBundle{
		KEKSalt:      resp.GetKekSalt(),
		KDFParams:    kdfParamsFromProto(resp.GetKdfParams()),
		EncryptedDEK: resp.GetEncryptedDek(),
	}, nil
}

func kdfParamsToProto(params crypt.KDFParams) *gophkeeperv1.KdfParams {
	return gophkeeperv1.KdfParams_builder{
		MemoryKib: proto.Uint32(params.MemoryKiB),
		Time:      proto.Uint32(params.Time),
		Threads:   proto.Uint32(uint32(params.Threads)),
	}.Build()
}

func kdfParamsFromProto(params *gophkeeperv1.KdfParams) crypt.KDFParams {
	return crypt.KDFParams{
		MemoryKiB: params.GetMemoryKib(),
		Time:      params.GetTime(),
		Threads:   uint8(params.GetThreads()),
	}
}
