package grpcserver

import "context"

// contextKey is private, so no other package can collide with
// our context values.
type contextKey string

const userIDContextKey contextKey = "userID"

func withUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

// userIDFromContext returns the user ID that the auth
// interceptor stored for this call.
func userIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDContextKey).(string)
	return userID, ok && userID != ""
}
