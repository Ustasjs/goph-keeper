package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/ustasjs/goph-keeper/internal/secret"
	"github.com/ustasjs/goph-keeper/internal/server/auth"
	"github.com/ustasjs/goph-keeper/internal/server/grpcserver"
	"github.com/ustasjs/goph-keeper/internal/server/token"
	"github.com/ustasjs/goph-keeper/internal/tlscert"
)

// memStore is the server storage kept in memory. It implements
// what auth.Service and grpcserver need, so the tests run the
// real server code without a database.
type memStore struct {
	mu      sync.Mutex
	users   map[string]auth.User
	records map[string]secret.Secret
	nextID  int
}

func newMemStore() *memStore {
	return &memStore{users: map[string]auth.User{}, records: map[string]secret.Secret{}}
}

func (m *memStore) CreateUser(_ context.Context, user auth.NewUser) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[user.Login]; ok {
		return "", auth.ErrLoginTaken
	}
	id := "user-" + strconv.Itoa(len(m.users)+1)
	m.users[user.Login] = auth.User{
		ID:           id,
		Login:        user.Login,
		PasswordHash: user.PasswordHash,
		Crypto:       user.Crypto,
	}
	return id, nil
}

func (m *memStore) UserByLogin(_ context.Context, login string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[login]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return user, nil
}

func (m *memStore) CreateSecret(_ context.Context, userID string, ns secret.NewSecret) (secret.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	id := "00000000-0000-4000-8000-" + strconv.Itoa(100000000000+m.nextID)
	rec := secret.Secret{
		ID:        id,
		Type:      ns.Type,
		Name:      ns.Name,
		Metadata:  ns.Metadata,
		Payload:   ns.Payload,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.records[userID+"/"+id] = rec
	return rec, nil
}

func (m *memStore) SecretByID(_ context.Context, userID, id string) (secret.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.records[userID+"/"+id]
	if !ok {
		return secret.Secret{}, secret.ErrNotFound
	}
	return rec, nil
}

func (m *memStore) ListSecrets(_ context.Context, userID string) ([]secret.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var list []secret.Secret
	for key, rec := range m.records {
		if key[:len(userID)+1] == userID+"/" {
			list = append(list, rec)
		}
	}
	return list, nil
}

func (m *memStore) UpdateSecret(_ context.Context, userID string, upd secret.Update) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := userID + "/" + upd.ID
	rec, ok := m.records[key]
	if !ok {
		return 0, secret.ErrNotFound
	}
	rec.Name = upd.Name
	rec.Metadata = upd.Metadata
	rec.Payload = upd.Payload
	rec.Version++
	rec.UpdatedAt = time.Now()
	m.records[key] = rec
	return rec.Version, nil
}

func (m *memStore) DeleteSecret(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := userID + "/" + id
	if _, ok := m.records[key]; !ok {
		return secret.ErrNotFound
	}
	delete(m.records, key)
	return nil
}

// startServer runs the real gRPC server over TLS on a free local
// port. It returns the address and the CA file the client needs
// to trust the self-signed certificate.
func startServer(t *testing.T) (addr, caFile string) {
	t.Helper()

	certPEM, keyPEM, err := tlscert.GeneratePEM()
	require.NoError(t, err)
	tlsConfig, err := tlscert.ServerConfig(certPEM, keyPEM)
	require.NoError(t, err)

	caFile = filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, certPEM, 0o600))

	store := newMemStore()
	tokens := token.New([]byte("test-secret"), time.Hour)
	srv := grpcserver.New("", auth.New(store, tokens), store, tokens, zap.NewNop(), tlsConfig)

	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	return lis.Addr().String(), caFile
}
