package remote

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// authMetadataKey carries the token in both directions. It must
// match the key used by the server.
const authMetadataKey = "authorization"

// tokenInterceptor adds the saved token to every call and saves
// the fresh token that comes back in the answer header. This is
// the client half of the sliding session: while the user works,
// the session never expires.
func tokenInterceptor(tokens TokenStore) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any,
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		if token, err := tokens.Token(); err == nil && token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, authMetadataKey, token)
		}

		var header metadata.MD
		opts = append(opts, grpc.Header(&header))

		err := invoker(ctx, method, req, reply, cc, opts...)

		// Save the fresh token even when the call failed: the
		// server may still have sent one.
		if values := header.Get(authMetadataKey); len(values) > 0 && values[0] != "" {
			// A save error must not hide the call error. The
			// worst case is one extra login later.
			_ = tokens.SaveToken(values[0])
		}

		return err
	}
}
