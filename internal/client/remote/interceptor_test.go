package remote

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// callInterceptor runs the interceptor with a fake invoker, so
// the test needs no connection. The invoker reports the token it
// received and writes freshToken into the answer header, the way
// the real server does.
func callInterceptor(t *testing.T, tokens TokenStore, freshToken string, invokerErr error) string {
	t.Helper()

	var gotToken string
	invoker := func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, opts ...grpc.CallOption) error {
		if md, ok := metadata.FromOutgoingContext(ctx); ok {
			if values := md.Get(authMetadataKey); len(values) > 0 {
				gotToken = values[0]
			}
		}

		if freshToken != "" {
			// grpc.Header gives the interceptor a place to
			// receive the answer header; fill it here.
			for _, opt := range opts {
				if header, ok := opt.(grpc.HeaderCallOption); ok {
					*header.HeaderAddr = metadata.Pairs(authMetadataKey, freshToken)
				}
			}
		}
		return invokerErr
	}

	err := tokenInterceptor(tokens)(context.Background(), "/test/Method", nil, nil, nil, invoker)
	if invokerErr != nil {
		require.ErrorIs(t, err, invokerErr)
	} else {
		require.NoError(t, err)
	}
	return gotToken
}

func TestTokenInterceptor_sendsSavedToken(t *testing.T) {
	t.Parallel()

	tokens := &memoryTokenStore{token: "saved-token"}

	got := callInterceptor(t, tokens, "", nil)
	assert.Equal(t, "saved-token", got)
}

func TestTokenInterceptor_noTokenYet(t *testing.T) {
	t.Parallel()

	tokens := &memoryTokenStore{}

	// Register and Login run before there is any token.
	got := callInterceptor(t, tokens, "", nil)
	assert.Empty(t, got)
}

func TestTokenInterceptor_savesFreshToken(t *testing.T) {
	t.Parallel()

	tokens := &memoryTokenStore{token: "old-token"}

	got := callInterceptor(t, tokens, "fresh-token", nil)

	// The call carried the old token, and the new one is saved:
	// this is what keeps the session alive.
	assert.Equal(t, "old-token", got)
	assert.Equal(t, "fresh-token", tokens.token)
}

func TestTokenInterceptor_savesFreshTokenAfterError(t *testing.T) {
	t.Parallel()

	tokens := &memoryTokenStore{token: "old-token"}
	callErr := errors.New("call failed")

	callInterceptor(t, tokens, "fresh-token", callErr)

	// The server may send a fresh token even when the call
	// fails, so it is saved anyway.
	assert.Equal(t, "fresh-token", tokens.token)
}

func TestTokenInterceptor_keepsOldTokenWhenNoneCameBack(t *testing.T) {
	t.Parallel()

	tokens := &memoryTokenStore{token: "old-token"}

	callInterceptor(t, tokens, "", nil)
	assert.Equal(t, "old-token", tokens.token)
}
