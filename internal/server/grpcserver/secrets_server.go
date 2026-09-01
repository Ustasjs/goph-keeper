package grpcserver

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ustasjs/goph-keeper/internal/secret"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// secretsServer handles the SecretsService RPCs.
type secretsServer struct {
	gophkeeperv1.UnimplementedSecretsServiceServer

	secrets SecretStore
	log     *zap.Logger
}

func (s *secretsServer) CreateSecret(ctx context.Context, req *gophkeeperv1.CreateSecretRequest) (*gophkeeperv1.CreateSecretResponse, error) {
	userID, ok := userIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user")
	}

	recType, ok := typeFromProto(req.GetType())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unknown secret type")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.GetEncryptedPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "encrypted_payload is required")
	}

	created, err := s.secrets.CreateSecret(ctx, userID, secret.NewSecret{
		Type:     recType,
		Name:     req.GetName(),
		Metadata: req.GetMetadata(),
		Payload:  req.GetEncryptedPayload(),
	})
	if err != nil {
		s.log.Error("create secret", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return gophkeeperv1.CreateSecretResponse_builder{
		Id:      proto.String(created.ID),
		Version: proto.Int64(created.Version),
	}.Build(), nil
}

func (s *secretsServer) GetSecret(ctx context.Context, req *gophkeeperv1.GetSecretRequest) (*gophkeeperv1.GetSecretResponse, error) {
	userID, ok := userIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user")
	}
	if _, err := uuid.Parse(req.GetId()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "id is not a valid UUID")
	}

	rec, err := s.secrets.SecretByID(ctx, userID, req.GetId())
	if err != nil {
		if errors.Is(err, secret.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		s.log.Error("get secret", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return gophkeeperv1.GetSecretResponse_builder{Secret: secretToProto(rec)}.Build(), nil
}

func (s *secretsServer) ListSecrets(ctx context.Context, _ *gophkeeperv1.ListSecretsRequest) (*gophkeeperv1.ListSecretsResponse, error) {
	userID, ok := userIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user")
	}

	list, err := s.secrets.ListSecrets(ctx, userID)
	if err != nil {
		s.log.Error("list secrets", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	out := make([]*gophkeeperv1.Secret, 0, len(list))
	for _, rec := range list {
		out = append(out, secretToProto(rec))
	}
	return gophkeeperv1.ListSecretsResponse_builder{Secrets: out}.Build(), nil
}

func (s *secretsServer) UpdateSecret(ctx context.Context, req *gophkeeperv1.UpdateSecretRequest) (*gophkeeperv1.UpdateSecretResponse, error) {
	userID, ok := userIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user")
	}
	if _, err := uuid.Parse(req.GetId()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "id is not a valid UUID")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.GetEncryptedPayload()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "encrypted_payload is required")
	}

	version, err := s.secrets.UpdateSecret(ctx, userID, secret.Update{
		ID:       req.GetId(),
		Name:     req.GetName(),
		Metadata: req.GetMetadata(),
		Payload:  req.GetEncryptedPayload(),
	})
	if err != nil {
		if errors.Is(err, secret.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		s.log.Error("update secret", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return gophkeeperv1.UpdateSecretResponse_builder{Version: proto.Int64(version)}.Build(), nil
}

func (s *secretsServer) DeleteSecret(ctx context.Context, req *gophkeeperv1.DeleteSecretRequest) (*gophkeeperv1.DeleteSecretResponse, error) {
	userID, ok := userIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user")
	}
	if _, err := uuid.Parse(req.GetId()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "id is not a valid UUID")
	}

	if err := s.secrets.DeleteSecret(ctx, userID, req.GetId()); err != nil {
		if errors.Is(err, secret.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		s.log.Error("delete secret", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &gophkeeperv1.DeleteSecretResponse{}, nil
}

var typeToProtoMap = map[secret.Type]gophkeeperv1.SecretType{
	secret.TypeLoginPassword: gophkeeperv1.SecretType_SECRET_TYPE_LOGIN_PASSWORD,
	secret.TypeText:          gophkeeperv1.SecretType_SECRET_TYPE_TEXT,
	secret.TypeBinary:        gophkeeperv1.SecretType_SECRET_TYPE_BINARY,
	secret.TypeCard:          gophkeeperv1.SecretType_SECRET_TYPE_CARD,
}

var typeFromProtoMap = map[gophkeeperv1.SecretType]secret.Type{
	gophkeeperv1.SecretType_SECRET_TYPE_LOGIN_PASSWORD: secret.TypeLoginPassword,
	gophkeeperv1.SecretType_SECRET_TYPE_TEXT:           secret.TypeText,
	gophkeeperv1.SecretType_SECRET_TYPE_BINARY:         secret.TypeBinary,
	gophkeeperv1.SecretType_SECRET_TYPE_CARD:           secret.TypeCard,
}

func typeFromProto(t gophkeeperv1.SecretType) (secret.Type, bool) {
	recType, ok := typeFromProtoMap[t]
	return recType, ok
}

func secretToProto(rec secret.Secret) *gophkeeperv1.Secret {
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
