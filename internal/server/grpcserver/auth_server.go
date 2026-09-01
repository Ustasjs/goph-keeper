package grpcserver

import (
	"context"
	"errors"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ustasjs/goph-keeper/internal/server/auth"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// authServer handles the AuthService RPCs.
type authServer struct {
	gophkeeperv1.UnimplementedAuthServiceServer

	auth AuthService
	log  *zap.Logger
}

func (s *authServer) Register(ctx context.Context, req *gophkeeperv1.RegisterRequest) (*gophkeeperv1.RegisterResponse, error) {
	if req.GetLogin() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "login and password are required")
	}
	crypto, err := cryptoFromProto(req.GetKekSalt(), req.GetKdfParams(), req.GetEncryptedDek())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	authToken, err := s.auth.Register(ctx, req.GetLogin(), req.GetPassword(), crypto)
	if err != nil {
		if errors.Is(err, auth.ErrLoginTaken) {
			return nil, status.Error(codes.AlreadyExists, "login is taken")
		}
		s.log.Error("register user", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return gophkeeperv1.RegisterResponse_builder{Token: proto.String(authToken)}.Build(), nil
}

func (s *authServer) Login(ctx context.Context, req *gophkeeperv1.LoginRequest) (*gophkeeperv1.LoginResponse, error) {
	authToken, crypto, err := s.auth.Login(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid login or password")
		}
		s.log.Error("login user", zap.Error(err))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return gophkeeperv1.LoginResponse_builder{
		Token:        proto.String(authToken),
		KekSalt:      crypto.KEKSalt,
		KdfParams:    kdfParamsToProto(crypto.KDFParams),
		EncryptedDek: crypto.EncryptedDEK,
	}.Build(), nil
}

// cryptoFromProto validates and converts the client crypto
// fields. The server cannot check their content, only that they
// are present and sane.
func cryptoFromProto(kekSalt []byte, params *gophkeeperv1.KdfParams, encryptedDEK []byte) (auth.CryptoBundle, error) {
	if len(kekSalt) == 0 {
		return auth.CryptoBundle{}, errors.New("kek_salt is required")
	}
	if len(encryptedDEK) == 0 {
		return auth.CryptoBundle{}, errors.New("encrypted_dek is required")
	}
	if params.GetMemoryKib() == 0 || params.GetTime() == 0 || params.GetThreads() == 0 {
		return auth.CryptoBundle{}, errors.New("kdf_params fields must be positive")
	}
	return auth.CryptoBundle{
		KEKSalt: kekSalt,
		KDFParams: auth.KDFParams{
			MemoryKiB: params.GetMemoryKib(),
			Time:      params.GetTime(),
			Threads:   params.GetThreads(),
		},
		EncryptedDEK: encryptedDEK,
	}, nil
}

func kdfParamsToProto(params auth.KDFParams) *gophkeeperv1.KdfParams {
	return gophkeeperv1.KdfParams_builder{
		MemoryKib: proto.Uint32(params.MemoryKiB),
		Time:      proto.Uint32(params.Time),
		Threads:   proto.Uint32(params.Threads),
	}.Build()
}
