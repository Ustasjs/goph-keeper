package grpcserver

import (
	"context"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthMetadataKey is the metadata key that carries the JWT, both
// in requests and in responses.
const AuthMetadataKey = "authorization"

// publicServicePrefix marks the RPCs that need no token.
const publicServicePrefix = "/gophkeeper.v1.AuthService/"

// authInterceptor guards every non-public RPC: it checks the JWT
// from the request metadata and puts the user ID into the
// context. On success it also sends a fresh token back in the
// response header — this is the sliding session: every call
// extends it.
func authInterceptor(tokens TokenService, log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.HasPrefix(info.FullMethod, publicServicePrefix) {
			return handler(ctx, req)
		}

		tokenString, ok := tokenFromMetadata(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}

		userID, err := tokens.ParseUserID(tokenString)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		fresh, err := tokens.Generate(userID)
		if err != nil {
			// The old token still works, so only log this.
			log.Error("generate fresh token", zap.Error(err))
		} else if err := grpc.SetHeader(ctx, metadata.Pairs(AuthMetadataKey, fresh)); err != nil {
			log.Error("send fresh token", zap.Error(err))
		}

		return handler(withUserID(ctx, userID), req)
	}
}

// tokenFromMetadata returns the bare JWT from the authorization
// metadata header.
func tokenFromMetadata(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	values := md.Get(AuthMetadataKey)
	if len(values) == 0 {
		return "", false
	}

	tokenString := strings.TrimSpace(values[0])
	return tokenString, tokenString != ""
}
