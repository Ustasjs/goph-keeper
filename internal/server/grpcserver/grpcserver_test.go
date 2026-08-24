package grpcserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/ustasjs/goph-keeper/internal/server/auth"
	"github.com/ustasjs/goph-keeper/internal/server/secret"
	"github.com/ustasjs/goph-keeper/internal/server/token"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

type fakeAuthService struct {
	err    error
	crypto auth.CryptoBundle
}

func (f *fakeAuthService) Register(_ context.Context, _, _ string, _ auth.CryptoBundle) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "registered-token", nil
}

func (f *fakeAuthService) Login(_ context.Context, _, _ string) (string, auth.CryptoBundle, error) {
	if f.err != nil {
		return "", auth.CryptoBundle{}, f.err
	}
	return "login-token", f.crypto, nil
}

type fakeSecretStore struct {
	err     error
	secret  secret.Secret
	created secret.NewSecret
	userID  string
}

func (f *fakeSecretStore) CreateSecret(_ context.Context, userID string, ns secret.NewSecret) (secret.Secret, error) {
	f.userID = userID
	f.created = ns
	if f.err != nil {
		return secret.Secret{}, f.err
	}
	return f.secret, nil
}

func (f *fakeSecretStore) SecretByID(_ context.Context, userID, _ string) (secret.Secret, error) {
	f.userID = userID
	if f.err != nil {
		return secret.Secret{}, f.err
	}
	return f.secret, nil
}

func (f *fakeSecretStore) ListSecrets(_ context.Context, userID string) ([]secret.Secret, error) {
	f.userID = userID
	if f.err != nil {
		return nil, f.err
	}
	return []secret.Secret{f.secret}, nil
}

func (f *fakeSecretStore) UpdateSecret(_ context.Context, userID string, _ secret.Update) (int64, error) {
	f.userID = userID
	if f.err != nil {
		return 0, f.err
	}
	return 2, nil
}

func (f *fakeSecretStore) DeleteSecret(_ context.Context, userID, _ string) error {
	f.userID = userID
	return f.err
}

const testUUID = "b3f1a1c0-0000-4000-8000-000000000001"

// newTestClients serves the API over an in-memory listener and
// returns ready-to-use clients.
func newTestClients(t *testing.T, authSvc AuthService, secrets SecretStore, tokens TokenService) (gophkeeperv1.AuthServiceClient, gophkeeperv1.SecretsServiceClient) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := New("bufnet", authSvc, secrets, tokens, zap.NewNop(), nil)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return gophkeeperv1.NewAuthServiceClient(conn), gophkeeperv1.NewSecretsServiceClient(conn)
}

func testTokens(t *testing.T) *token.Service {
	t.Helper()
	return token.New([]byte("test-secret"), time.Hour)
}

func validRegisterRequest() *gophkeeperv1.RegisterRequest {
	return gophkeeperv1.RegisterRequest_builder{
		Login:    proto.String("alice"),
		Password: proto.String("password"),
		KekSalt:  []byte("salt"),
		KdfParams: gophkeeperv1.KdfParams_builder{
			MemoryKib: proto.Uint32(64 * 1024),
			Time:      proto.Uint32(1),
			Threads:   proto.Uint32(4),
		}.Build(),
		EncryptedDek: []byte("wrapped-dek"),
	}.Build()
}

func authedContext(t *testing.T, tokens *token.Service, userID string) context.Context {
	t.Helper()
	tokenString, err := tokens.Generate(userID)
	require.NoError(t, err)
	return metadata.AppendToOutgoingContext(context.Background(), AuthMetadataKey, tokenString)
}

func TestAuthServer_Register(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		authClient, _ := newTestClients(t, &fakeAuthService{}, &fakeSecretStore{}, testTokens(t))

		resp, err := authClient.Register(context.Background(), validRegisterRequest())
		require.NoError(t, err)
		assert.Equal(t, "registered-token", resp.GetToken())
	})

	t.Run("login taken", func(t *testing.T) {
		t.Parallel()
		authClient, _ := newTestClients(t, &fakeAuthService{err: auth.ErrLoginTaken}, &fakeSecretStore{}, testTokens(t))

		_, err := authClient.Register(context.Background(), validRegisterRequest())
		assert.Equal(t, codes.AlreadyExists, status.Code(err))
	})

	t.Run("empty login", func(t *testing.T) {
		t.Parallel()
		authClient, _ := newTestClients(t, &fakeAuthService{}, &fakeSecretStore{}, testTokens(t))

		req := validRegisterRequest()
		req.SetLogin("")
		_, err := authClient.Register(context.Background(), req)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("bad kdf params", func(t *testing.T) {
		t.Parallel()
		authClient, _ := newTestClients(t, &fakeAuthService{}, &fakeSecretStore{}, testTokens(t))

		req := validRegisterRequest()
		req.SetKdfParams(gophkeeperv1.KdfParams_builder{}.Build())
		_, err := authClient.Register(context.Background(), req)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

func TestAuthServer_Login(t *testing.T) {
	t.Parallel()

	t.Run("success returns crypto material", func(t *testing.T) {
		t.Parallel()
		crypto := auth.CryptoBundle{
			KEKSalt:      []byte("salt"),
			KDFParams:    auth.KDFParams{MemoryKiB: 65536, Time: 1, Threads: 4},
			EncryptedDEK: []byte("wrapped-dek"),
		}
		authClient, _ := newTestClients(t, &fakeAuthService{crypto: crypto}, &fakeSecretStore{}, testTokens(t))

		req := gophkeeperv1.LoginRequest_builder{Login: proto.String("alice"), Password: proto.String("password")}.Build()
		resp, err := authClient.Login(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "login-token", resp.GetToken())
		assert.Equal(t, []byte("salt"), resp.GetKekSalt())
		assert.Equal(t, []byte("wrapped-dek"), resp.GetEncryptedDek())
		assert.Equal(t, uint32(65536), resp.GetKdfParams().GetMemoryKib())
	})

	t.Run("wrong credentials", func(t *testing.T) {
		t.Parallel()
		authClient, _ := newTestClients(t, &fakeAuthService{err: auth.ErrInvalidCredentials}, &fakeSecretStore{}, testTokens(t))

		req := gophkeeperv1.LoginRequest_builder{Login: proto.String("alice"), Password: proto.String("bad")}.Build()
		_, err := authClient.Login(context.Background(), req)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestAuthInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("no token", func(t *testing.T) {
		t.Parallel()
		_, secretsClient := newTestClients(t, &fakeAuthService{}, &fakeSecretStore{}, testTokens(t))

		_, err := secretsClient.ListSecrets(context.Background(), &gophkeeperv1.ListSecretsRequest{})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("garbage token", func(t *testing.T) {
		t.Parallel()
		_, secretsClient := newTestClients(t, &fakeAuthService{}, &fakeSecretStore{}, testTokens(t))

		ctx := metadata.AppendToOutgoingContext(context.Background(), AuthMetadataKey, "garbage")
		_, err := secretsClient.ListSecrets(ctx, &gophkeeperv1.ListSecretsRequest{})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("valid token reaches store and slides", func(t *testing.T) {
		t.Parallel()
		tokens := testTokens(t)
		store := &fakeSecretStore{}
		_, secretsClient := newTestClients(t, &fakeAuthService{}, store, tokens)

		var header metadata.MD
		_, err := secretsClient.ListSecrets(authedContext(t, tokens, "user-42"),
			&gophkeeperv1.ListSecretsRequest{}, grpc.Header(&header))
		require.NoError(t, err)

		// The handler saw the user from the token.
		assert.Equal(t, "user-42", store.userID)

		// The response carries a fresh working token.
		fresh := header.Get(AuthMetadataKey)
		require.Len(t, fresh, 1)
		userID, err := tokens.ParseUserID(fresh[0])
		require.NoError(t, err)
		assert.Equal(t, "user-42", userID)
	})
}

func TestSecretsServer(t *testing.T) {
	t.Parallel()

	t.Run("create validates input", func(t *testing.T) {
		t.Parallel()
		tokens := testTokens(t)
		_, secretsClient := newTestClients(t, &fakeAuthService{}, &fakeSecretStore{}, tokens)
		ctx := authedContext(t, tokens, "user-1")

		tests := []struct {
			name string
			req  *gophkeeperv1.CreateSecretRequest
		}{
			{
				name: "unknown type",
				req: gophkeeperv1.CreateSecretRequest_builder{
					Name:             proto.String("x"),
					EncryptedPayload: []byte("blob"),
				}.Build(),
			},
			{
				name: "empty name",
				req: gophkeeperv1.CreateSecretRequest_builder{
					Type:             gophkeeperv1.SecretType_SECRET_TYPE_TEXT.Enum(),
					EncryptedPayload: []byte("blob"),
				}.Build(),
			},
			{
				name: "empty payload",
				req: gophkeeperv1.CreateSecretRequest_builder{
					Type: gophkeeperv1.SecretType_SECRET_TYPE_TEXT.Enum(),
					Name: proto.String("x"),
				}.Build(),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := secretsClient.CreateSecret(ctx, tt.req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			})
		}
	})

	t.Run("create success", func(t *testing.T) {
		t.Parallel()
		tokens := testTokens(t)
		store := &fakeSecretStore{secret: secret.Secret{ID: testUUID, Version: 1}}
		_, secretsClient := newTestClients(t, &fakeAuthService{}, store, tokens)

		req := gophkeeperv1.CreateSecretRequest_builder{
			Type:             gophkeeperv1.SecretType_SECRET_TYPE_CARD.Enum(),
			Name:             proto.String("my card"),
			Metadata:         proto.String("bank note"),
			EncryptedPayload: []byte("blob"),
		}.Build()
		resp, err := secretsClient.CreateSecret(authedContext(t, tokens, "user-1"), req)
		require.NoError(t, err)
		assert.Equal(t, testUUID, resp.GetId())
		assert.Equal(t, int64(1), resp.GetVersion())
		assert.Equal(t, secret.TypeCard, store.created.Type)
		assert.Equal(t, "my card", store.created.Name)
		assert.Equal(t, "bank note", store.created.Metadata)
	})

	t.Run("get maps errors", func(t *testing.T) {
		t.Parallel()
		tokens := testTokens(t)
		store := &fakeSecretStore{err: secret.ErrNotFound}
		_, secretsClient := newTestClients(t, &fakeAuthService{}, store, tokens)
		ctx := authedContext(t, tokens, "user-1")

		badID := gophkeeperv1.GetSecretRequest_builder{Id: proto.String("not-a-uuid")}.Build()
		_, err := secretsClient.GetSecret(ctx, badID)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))

		missing := gophkeeperv1.GetSecretRequest_builder{Id: proto.String(testUUID)}.Build()
		_, err = secretsClient.GetSecret(ctx, missing)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("update and delete map not found", func(t *testing.T) {
		t.Parallel()
		tokens := testTokens(t)
		store := &fakeSecretStore{err: secret.ErrNotFound}
		_, secretsClient := newTestClients(t, &fakeAuthService{}, store, tokens)
		ctx := authedContext(t, tokens, "user-1")

		upd := gophkeeperv1.UpdateSecretRequest_builder{
			Id:               proto.String(testUUID),
			Name:             proto.String("x"),
			EncryptedPayload: []byte("blob"),
		}.Build()
		_, err := secretsClient.UpdateSecret(ctx, upd)
		assert.Equal(t, codes.NotFound, status.Code(err))

		del := gophkeeperv1.DeleteSecretRequest_builder{Id: proto.String(testUUID)}.Build()
		_, err = secretsClient.DeleteSecret(ctx, del)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("list returns records", func(t *testing.T) {
		t.Parallel()
		tokens := testTokens(t)
		store := &fakeSecretStore{secret: secret.Secret{
			ID: testUUID, Type: secret.TypeText, Name: "note", Version: 3,
		}}
		_, secretsClient := newTestClients(t, &fakeAuthService{}, store, tokens)

		resp, err := secretsClient.ListSecrets(authedContext(t, tokens, "user-1"), &gophkeeperv1.ListSecretsRequest{})
		require.NoError(t, err)
		require.Len(t, resp.GetSecrets(), 1)
		got := resp.GetSecrets()[0]
		assert.Equal(t, testUUID, got.GetId())
		assert.Equal(t, gophkeeperv1.SecretType_SECRET_TYPE_TEXT, got.GetType())
		assert.Equal(t, "note", got.GetName())
		assert.Equal(t, int64(3), got.GetVersion())
	})
}
