package remote

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ustasjs/goph-keeper/internal/secret"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

var (
	errTaken          = status.Error(codes.AlreadyExists, "login is taken")
	errBadCredentials = status.Error(codes.Unauthenticated, "invalid login or password")
)

// memoryTokenStore keeps the token in memory instead of a file.
type memoryTokenStore struct {
	mu    sync.Mutex
	token string
}

func (m *memoryTokenStore) Token() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token, nil
}

func (m *memoryTokenStore) SaveToken(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
	return nil
}

// fakeServer is a small in-memory version of the real server. It
// keeps records in a map and checks the token the same way the
// real auth interceptor does.
type fakeServer struct {
	gophkeeperv1.UnimplementedAuthServiceServer
	gophkeeperv1.UnimplementedSecretsServiceServer

	grpc *grpc.Server

	mu      sync.Mutex
	records map[string]secret.Secret
	nextID  int

	// token is the only token the server accepts. An empty value
	// means the server does not check tokens.
	token string
	// freshToken goes back in the answer header, like the
	// sliding session of the real server.
	freshToken string
	// gotToken is the token the last call carried.
	gotToken string

	bundle      CryptoBundle
	registerErr error
	loginErr    error
}

func (f *fakeServer) stop() {
	f.grpc.Stop()
}

func (f *fakeServer) Register(_ context.Context, _ *gophkeeperv1.RegisterRequest) (*gophkeeperv1.RegisterResponse, error) {
	if f.registerErr != nil {
		return nil, f.registerErr
	}
	return gophkeeperv1.RegisterResponse_builder{Token: proto.String("token-for-user-1")}.Build(), nil
}

func (f *fakeServer) Login(_ context.Context, _ *gophkeeperv1.LoginRequest) (*gophkeeperv1.LoginResponse, error) {
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	return gophkeeperv1.LoginResponse_builder{
		Token:   proto.String("token-for-user-1"),
		KekSalt: f.bundle.KEKSalt,
		KdfParams: gophkeeperv1.KdfParams_builder{
			MemoryKib: proto.Uint32(f.bundle.KDFParams.MemoryKiB),
			Time:      proto.Uint32(f.bundle.KDFParams.Time),
			Threads:   proto.Uint32(uint32(f.bundle.KDFParams.Threads)),
		}.Build(),
		EncryptedDek: f.bundle.EncryptedDEK,
	}.Build(), nil
}

func (f *fakeServer) CreateSecret(ctx context.Context, req *gophkeeperv1.CreateSecretRequest) (*gophkeeperv1.CreateSecretResponse, error) {
	if err := f.checkAuth(ctx); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.nextID++
	id := "id-" + strconv.Itoa(f.nextID)
	f.records[id] = secret.Secret{
		ID:       id,
		Type:     typeFromProtoMap[req.GetType()],
		Name:     req.GetName(),
		Metadata: req.GetMetadata(),
		Payload:  req.GetEncryptedPayload(),
		Version:  1,
	}
	return gophkeeperv1.CreateSecretResponse_builder{
		Id:      proto.String(id),
		Version: proto.Int64(1),
	}.Build(), nil
}

func (f *fakeServer) GetSecret(ctx context.Context, req *gophkeeperv1.GetSecretRequest) (*gophkeeperv1.GetSecretResponse, error) {
	if err := f.checkAuth(ctx); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	rec, ok := f.records[req.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return gophkeeperv1.GetSecretResponse_builder{Secret: recordToProto(rec)}.Build(), nil
}

func (f *fakeServer) ListSecrets(ctx context.Context, _ *gophkeeperv1.ListSecretsRequest) (*gophkeeperv1.ListSecretsResponse, error) {
	if err := f.checkAuth(ctx); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]*gophkeeperv1.Secret, 0, len(f.records))
	for _, rec := range f.records {
		out = append(out, recordToProto(rec))
	}
	return gophkeeperv1.ListSecretsResponse_builder{Secrets: out}.Build(), nil
}

func (f *fakeServer) UpdateSecret(ctx context.Context, req *gophkeeperv1.UpdateSecretRequest) (*gophkeeperv1.UpdateSecretResponse, error) {
	if err := f.checkAuth(ctx); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	rec, ok := f.records[req.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	rec.Name = req.GetName()
	rec.Metadata = req.GetMetadata()
	rec.Payload = req.GetEncryptedPayload()
	rec.Version++
	f.records[req.GetId()] = rec

	return gophkeeperv1.UpdateSecretResponse_builder{Version: proto.Int64(rec.Version)}.Build(), nil
}

func (f *fakeServer) DeleteSecret(ctx context.Context, req *gophkeeperv1.DeleteSecretRequest) (*gophkeeperv1.DeleteSecretResponse, error) {
	if err := f.checkAuth(ctx); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.records[req.GetId()]; !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	delete(f.records, req.GetId())
	return &gophkeeperv1.DeleteSecretResponse{}, nil
}

// checkAuth copies what the real auth interceptor does: it reads
// the token and sends a fresh one back.
func (f *fakeServer) checkAuth(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	var got string
	if values := md.Get(authMetadataKey); len(values) > 0 {
		got = values[0]
	}

	f.mu.Lock()
	f.gotToken = got
	want, fresh := f.token, f.freshToken
	f.mu.Unlock()

	if want != "" && got != want {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	if fresh != "" {
		_ = grpc.SetHeader(ctx, metadata.Pairs(authMetadataKey, fresh))
	}
	return nil
}

func recordToProto(rec secret.Secret) *gophkeeperv1.Secret {
	return gophkeeperv1.Secret_builder{
		Id:               proto.String(rec.ID),
		Type:             typeToProtoMap[rec.Type].Enum(),
		Name:             proto.String(rec.Name),
		Metadata:         proto.String(rec.Metadata),
		EncryptedPayload: rec.Payload,
		Version:          proto.Int64(rec.Version),
		CreatedAt:        timestamppb.New(rec.CreatedAt),
		UpdatedAt:        timestamppb.New(rec.UpdatedAt),
	}.Build()
}

// newTestClient serves a fake server over an in-memory listener
// and returns a Client that talks to it.
func newTestClient(t *testing.T) (*Client, *memoryTokenStore, *fakeServer) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := &fakeServer{grpc: grpc.NewServer(), records: map[string]secret.Secret{}}
	gophkeeperv1.RegisterAuthServiceServer(srv.grpc, srv)
	gophkeeperv1.RegisterSecretsServiceServer(srv.grpc, srv)

	go func() { _ = srv.grpc.Serve(lis) }()
	t.Cleanup(srv.grpc.Stop)

	tokens := &memoryTokenStore{}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			conn, err := lis.DialContext(ctx)
			if err != nil {
				return nil, errors.New("server is down")
			}
			return conn, nil
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(tokenInterceptor(tokens)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := &Client{
		conn:    conn,
		auth:    gophkeeperv1.NewAuthServiceClient(conn),
		secrets: gophkeeperv1.NewSecretsServiceClient(conn),
		tokens:  tokens,
	}
	return client, tokens, srv
}
