package remote

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	"github.com/ustasjs/goph-keeper/internal/secret"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// The tests below check what this package owns: the conversion
// between domain types and protobuf, and the mapping of gRPC
// status codes to our errors. The whole path over a real gRPC
// connection is covered by the CLI tests, which run a real
// server.

// stubAuthClient answers the AuthService calls.
type stubAuthClient struct {
	gophkeeperv1.AuthServiceClient

	registerReq *gophkeeperv1.RegisterRequest
	loginResp   *gophkeeperv1.LoginResponse
	err         error
}

func (s *stubAuthClient) Register(_ context.Context, req *gophkeeperv1.RegisterRequest, _ ...grpc.CallOption) (*gophkeeperv1.RegisterResponse, error) {
	s.registerReq = req
	if s.err != nil {
		return nil, s.err
	}
	return gophkeeperv1.RegisterResponse_builder{Token: proto.String("new-token")}.Build(), nil
}

func (s *stubAuthClient) Login(_ context.Context, _ *gophkeeperv1.LoginRequest, _ ...grpc.CallOption) (*gophkeeperv1.LoginResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.loginResp, nil
}

// stubSecretsClient answers the SecretsService calls.
type stubSecretsClient struct {
	gophkeeperv1.SecretsServiceClient

	createReq *gophkeeperv1.CreateSecretRequest
	updateReq *gophkeeperv1.UpdateSecretRequest
	deleteReq *gophkeeperv1.DeleteSecretRequest
	record    *gophkeeperv1.Secret
	err       error
}

func (s *stubSecretsClient) CreateSecret(_ context.Context, req *gophkeeperv1.CreateSecretRequest, _ ...grpc.CallOption) (*gophkeeperv1.CreateSecretResponse, error) {
	s.createReq = req
	if s.err != nil {
		return nil, s.err
	}
	return gophkeeperv1.CreateSecretResponse_builder{
		Id:      proto.String("new-id"),
		Version: proto.Int64(1),
	}.Build(), nil
}

func (s *stubSecretsClient) GetSecret(_ context.Context, _ *gophkeeperv1.GetSecretRequest, _ ...grpc.CallOption) (*gophkeeperv1.GetSecretResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return gophkeeperv1.GetSecretResponse_builder{Secret: s.record}.Build(), nil
}

func (s *stubSecretsClient) ListSecrets(_ context.Context, _ *gophkeeperv1.ListSecretsRequest, _ ...grpc.CallOption) (*gophkeeperv1.ListSecretsResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return gophkeeperv1.ListSecretsResponse_builder{
		Secrets: []*gophkeeperv1.Secret{s.record},
	}.Build(), nil
}

func (s *stubSecretsClient) UpdateSecret(_ context.Context, req *gophkeeperv1.UpdateSecretRequest, _ ...grpc.CallOption) (*gophkeeperv1.UpdateSecretResponse, error) {
	s.updateReq = req
	if s.err != nil {
		return nil, s.err
	}
	return gophkeeperv1.UpdateSecretResponse_builder{Version: proto.Int64(2)}.Build(), nil
}

func (s *stubSecretsClient) DeleteSecret(_ context.Context, req *gophkeeperv1.DeleteSecretRequest, _ ...grpc.CallOption) (*gophkeeperv1.DeleteSecretResponse, error) {
	s.deleteReq = req
	if s.err != nil {
		return nil, s.err
	}
	return &gophkeeperv1.DeleteSecretResponse{}, nil
}

// memoryTokenStore keeps the token in memory instead of a file.
type memoryTokenStore struct{ token string }

func (m *memoryTokenStore) Token() (string, error) { return m.token, nil }

func (m *memoryTokenStore) SaveToken(token string) error {
	m.token = token
	return nil
}

// newStubClient builds a Client with no connection behind it.
func newStubClient(authClient *stubAuthClient, secretsClient *stubSecretsClient) (*Client, *memoryTokenStore) {
	tokens := &memoryTokenStore{}
	return &Client{auth: authClient, secrets: secretsClient, tokens: tokens}, tokens
}

func testProtoSecret() *gophkeeperv1.Secret {
	return gophkeeperv1.Secret_builder{
		Id:               proto.String("id-1"),
		Type:             gophkeeperv1.SecretType_SECRET_TYPE_CARD.Enum(),
		Name:             proto.String("visa"),
		Metadata:         proto.String("bank"),
		EncryptedPayload: []byte("encrypted"),
		Version:          proto.Int64(3),
		CreatedAt:        timestamppb.New(timestamppb.Now().AsTime()),
		UpdatedAt:        timestamppb.New(timestamppb.Now().AsTime()),
	}.Build()
}

func TestClient_Register_sendsCryptoMaterial(t *testing.T) {
	t.Parallel()

	authClient := &stubAuthClient{}
	client, tokens := newStubClient(authClient, nil)

	bundle := CryptoBundle{
		KEKSalt:      []byte("salt"),
		KDFParams:    crypt.DefaultKDFParams(),
		EncryptedDEK: []byte("wrapped-dek"),
	}
	require.NoError(t, client.Register(context.Background(), "alice", "password", bundle))

	// The server gets the crypto material as it is.
	req := authClient.registerReq
	require.NotNil(t, req)
	assert.Equal(t, "alice", req.GetLogin())
	assert.Equal(t, bundle.KEKSalt, req.GetKekSalt())
	assert.Equal(t, bundle.EncryptedDEK, req.GetEncryptedDek())
	assert.Equal(t, bundle.KDFParams.MemoryKiB, req.GetKdfParams().GetMemoryKib())
	assert.Equal(t, uint32(bundle.KDFParams.Threads), req.GetKdfParams().GetThreads())

	assert.Equal(t, "new-token", tokens.token)
}

func TestClient_Register_loginTaken(t *testing.T) {
	t.Parallel()

	client, _ := newStubClient(&stubAuthClient{err: status.Error(codes.AlreadyExists, "taken")}, nil)

	err := client.Register(context.Background(), "alice", "password", CryptoBundle{})
	assert.ErrorIs(t, err, ErrLoginTaken)
}

func TestClient_Login_returnsCryptoMaterial(t *testing.T) {
	t.Parallel()

	params := crypt.DefaultKDFParams()
	authClient := &stubAuthClient{loginResp: gophkeeperv1.LoginResponse_builder{
		Token:   proto.String("login-token"),
		KekSalt: []byte("salt"),
		KdfParams: gophkeeperv1.KdfParams_builder{
			MemoryKib: proto.Uint32(params.MemoryKiB),
			Time:      proto.Uint32(params.Time),
			Threads:   proto.Uint32(uint32(params.Threads)),
		}.Build(),
		EncryptedDek: []byte("wrapped-dek"),
	}.Build()}
	client, tokens := newStubClient(authClient, nil)

	got, err := client.Login(context.Background(), "alice", "password")
	require.NoError(t, err)
	assert.Equal(t, []byte("salt"), got.KEKSalt)
	assert.Equal(t, []byte("wrapped-dek"), got.EncryptedDEK)
	assert.Equal(t, params, got.KDFParams)
	assert.Equal(t, "login-token", tokens.token)
}

func TestClient_Login_wrongCredentials(t *testing.T) {
	t.Parallel()

	client, _ := newStubClient(&stubAuthClient{err: status.Error(codes.Unauthenticated, "bad")}, nil)

	// For Login this code means bad credentials, not an expired
	// session.
	_, err := client.Login(context.Background(), "alice", "bad")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.NotErrorIs(t, err, ErrUnauthenticated)
}

func TestClient_CreateSecret_sendsFields(t *testing.T) {
	t.Parallel()

	secretsClient := &stubSecretsClient{}
	client, _ := newStubClient(nil, secretsClient)

	id, err := client.CreateSecret(context.Background(), secret.NewSecret{
		Type:     secret.TypeCard,
		Name:     "visa",
		Metadata: "bank",
		Payload:  []byte("encrypted"),
	})
	require.NoError(t, err)
	assert.Equal(t, "new-id", id)

	req := secretsClient.createReq
	require.NotNil(t, req)
	assert.Equal(t, gophkeeperv1.SecretType_SECRET_TYPE_CARD, req.GetType())
	assert.Equal(t, "visa", req.GetName())
	assert.Equal(t, "bank", req.GetMetadata())
	assert.Equal(t, []byte("encrypted"), req.GetEncryptedPayload())
}

func TestClient_CreateSecret_unknownType(t *testing.T) {
	t.Parallel()

	client, _ := newStubClient(nil, &stubSecretsClient{})

	_, err := client.CreateSecret(context.Background(), secret.NewSecret{
		Type: "no-such-type", Name: "x", Payload: []byte("blob"),
	})
	assert.Error(t, err)
}

func TestClient_GetSecret_convertsRecord(t *testing.T) {
	t.Parallel()

	client, _ := newStubClient(nil, &stubSecretsClient{record: testProtoSecret()})

	got, err := client.GetSecret(context.Background(), "id-1")
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)
	assert.Equal(t, secret.TypeCard, got.Type)
	assert.Equal(t, "visa", got.Name)
	assert.Equal(t, "bank", got.Metadata)
	assert.Equal(t, []byte("encrypted"), got.Payload)
	assert.Equal(t, int64(3), got.Version)
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestClient_ListSecrets(t *testing.T) {
	t.Parallel()

	client, _ := newStubClient(nil, &stubSecretsClient{record: testProtoSecret()})

	list, err := client.ListSecrets(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, secret.TypeCard, list[0].Type)
	assert.Equal(t, "visa", list[0].Name)
}

func TestClient_UpdateAndDelete(t *testing.T) {
	t.Parallel()

	secretsClient := &stubSecretsClient{}
	client, _ := newStubClient(nil, secretsClient)
	ctx := context.Background()

	require.NoError(t, client.UpdateSecret(ctx, secret.Update{
		ID: "id-1", Name: "renamed", Metadata: "note", Payload: []byte("new"),
	}))
	require.NotNil(t, secretsClient.updateReq)
	assert.Equal(t, "renamed", secretsClient.updateReq.GetName())
	assert.Equal(t, []byte("new"), secretsClient.updateReq.GetEncryptedPayload())

	require.NoError(t, client.DeleteSecret(ctx, "id-1"))
	require.NotNil(t, secretsClient.deleteReq)
	assert.Equal(t, "id-1", secretsClient.deleteReq.GetId())
}

func TestClient_errorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code codes.Code
		want error
	}{
		{"not found", codes.NotFound, ErrNotFound},
		{"expired session", codes.Unauthenticated, ErrUnauthenticated},
		{"server down", codes.Unavailable, ErrUnavailable},
		{"deadline", codes.DeadlineExceeded, ErrUnavailable},
		{"too large", codes.ResourceExhausted, ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, _ := newStubClient(nil, &stubSecretsClient{err: status.Error(tt.code, "boom")})

			_, err := client.GetSecret(context.Background(), "id-1")
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestWrapError(t *testing.T) {
	t.Parallel()

	assert.NoError(t, wrapError("op", nil))

	// A plain error keeps its text.
	err := wrapError("op", errors.New("something broke"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "something broke")

	// InvalidArgument keeps the server message: it explains what
	// exactly was wrong.
	err = wrapError("op", status.Error(codes.InvalidArgument, "name is required"))
	assert.Contains(t, err.Error(), "name is required")
}
