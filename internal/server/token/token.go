// Package token issues and checks the auth tokens (JWT, HS256).
package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken covers every bad token: wrong signature,
// expired, malformed, or empty user ID.
var ErrInvalidToken = errors.New("invalid token")

// Claims is the token payload: the user ID plus standard fields.
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// Service signs and parses tokens with one shared secret.
type Service struct {
	secret []byte
	ttl    time.Duration
}

// New builds a Service. The secret comes from config and must
// not be empty; ttl is the lifetime of one token.
func New(secret []byte, ttl time.Duration) *Service {
	return &Service{secret: secret, ttl: ttl}
}

// Generate returns a signed token for userID.
func (s *Service) Generate(userID string) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// ParseUserID checks the token and returns the user ID from it.
func (s *Service) ParseUserID(tokenString string) (string, error) {
	parsed, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid || claims.UserID == "" {
		return "", ErrInvalidToken
	}
	return claims.UserID, nil
}
