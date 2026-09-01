package remote

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/ustasjs/goph-keeper/internal/secret"
	gophkeeperv1 "github.com/ustasjs/goph-keeper/pkg/proto/gophkeeper/v1"
)

// CreateSecret saves a new record and returns its ID. The
// payload must already be encrypted.
func (c *Client) CreateSecret(ctx context.Context, ns secret.NewSecret) (string, error) {
	protoType, ok := typeToProto(ns.Type)
	if !ok {
		return "", fmt.Errorf("unknown secret type %q", ns.Type)
	}

	req := gophkeeperv1.CreateSecretRequest_builder{
		Type:             protoType.Enum(),
		Name:             proto.String(ns.Name),
		Metadata:         proto.String(ns.Metadata),
		EncryptedPayload: ns.Payload,
	}.Build()

	resp, err := c.secrets.CreateSecret(ctx, req)
	if err != nil {
		return "", wrapError("create secret", err)
	}
	return resp.GetId(), nil
}

// GetSecret returns one record. The payload comes encrypted.
func (c *Client) GetSecret(ctx context.Context, id string) (secret.Secret, error) {
	req := gophkeeperv1.GetSecretRequest_builder{Id: proto.String(id)}.Build()

	resp, err := c.secrets.GetSecret(ctx, req)
	if err != nil {
		return secret.Secret{}, wrapError("get secret", err)
	}
	return secretFromProto(resp.GetSecret()), nil
}

// ListSecrets returns all records of the user. Names and
// metadata are open, so the list is readable without the master
// password.
func (c *Client) ListSecrets(ctx context.Context) ([]secret.Secret, error) {
	resp, err := c.secrets.ListSecrets(ctx, &gophkeeperv1.ListSecretsRequest{})
	if err != nil {
		return nil, wrapError("list secrets", err)
	}

	list := make([]secret.Secret, 0, len(resp.GetSecrets()))
	for _, rec := range resp.GetSecrets() {
		list = append(list, secretFromProto(rec))
	}
	return list, nil
}

// UpdateSecret replaces the name, the metadata and the payload
// of a record. The server uses last write wins, so the call
// never fails because of an old version.
func (c *Client) UpdateSecret(ctx context.Context, upd secret.Update) error {
	req := gophkeeperv1.UpdateSecretRequest_builder{
		Id:               proto.String(upd.ID),
		Name:             proto.String(upd.Name),
		Metadata:         proto.String(upd.Metadata),
		EncryptedPayload: upd.Payload,
	}.Build()

	if _, err := c.secrets.UpdateSecret(ctx, req); err != nil {
		return wrapError("update secret", err)
	}
	return nil
}

// DeleteSecret removes a record.
func (c *Client) DeleteSecret(ctx context.Context, id string) error {
	req := gophkeeperv1.DeleteSecretRequest_builder{Id: proto.String(id)}.Build()

	if _, err := c.secrets.DeleteSecret(ctx, req); err != nil {
		return wrapError("delete secret", err)
	}
	return nil
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

func typeToProto(t secret.Type) (gophkeeperv1.SecretType, bool) {
	protoType, ok := typeToProtoMap[t]
	return protoType, ok
}

func secretFromProto(rec *gophkeeperv1.Secret) secret.Secret {
	return secret.Secret{
		ID:        rec.GetId(),
		Type:      typeFromProtoMap[rec.GetType()],
		Name:      rec.GetName(),
		Metadata:  rec.GetMetadata(),
		Payload:   rec.GetEncryptedPayload(),
		Version:   rec.GetVersion(),
		CreatedAt: rec.GetCreatedAt().AsTime(),
		UpdatedAt: rec.GetUpdatedAt().AsTime(),
	}
}
