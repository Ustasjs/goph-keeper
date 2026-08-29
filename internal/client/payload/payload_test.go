package payload

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	"github.com/ustasjs/goph-keeper/internal/secret"
)

func TestMarshal_roundTripEveryType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content any
		want    any
	}{
		{
			name:    "login password",
			content: &LoginPassword{Login: "alice", Password: "s3cret"},
			want:    &LoginPassword{},
		},
		{
			name:    "text",
			content: &Text{Text: "some private note"},
			want:    &Text{},
		},
		{
			name:    "binary",
			content: &Binary{Filename: "scan.pdf", Data: []byte{0x00, 0x01, 0xFF}},
			want:    &Binary{},
		},
		{
			name: "card",
			content: &Card{
				Number: "4111111111111111",
				Holder: "ALICE SMITH",
				Expiry: "12/30",
				CVV:    "123",
			},
			want: &Card{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := Marshal(tt.content)
			require.NoError(t, err)

			require.NoError(t, Unmarshal(data, tt.want))
			assert.Equal(t, tt.content, tt.want)
		})
	}
}

func TestMarshal_tooLarge(t *testing.T) {
	t.Parallel()

	big := &Binary{Filename: "big.bin", Data: make([]byte, MaxSize+1)}

	_, err := Marshal(big)
	assert.ErrorIs(t, err, ErrTooLarge)
}

func TestUnmarshal_brokenJSON(t *testing.T) {
	t.Parallel()

	var content Text
	assert.Error(t, Unmarshal([]byte("not json"), &content))
}

func TestNew_everyType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		recordType secret.Type
		want       any
	}{
		{secret.TypeLoginPassword, &LoginPassword{}},
		{secret.TypeText, &Text{}},
		{secret.TypeBinary, &Binary{}},
		{secret.TypeCard, &Card{}},
	}
	for _, tt := range tests {
		t.Run(string(tt.recordType), func(t *testing.T) {
			t.Parallel()

			got, err := New(tt.recordType)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	_, err := New("no-such-type")
	assert.Error(t, err)
}

func TestMarshal_encryptedForServer(t *testing.T) {
	t.Parallel()

	// The whole point of the client: what leaves the machine
	// must not contain the secret values.
	content := &Card{Number: "4111111111111111", Holder: "ALICE", Expiry: "12/30", CVV: "123"}

	data, err := Marshal(content)
	require.NoError(t, err)

	dek, err := crypt.NewDEK()
	require.NoError(t, err)
	blob, err := crypt.Encrypt(data, dek)
	require.NoError(t, err)

	assert.False(t, bytes.Contains(blob, []byte(content.Number)), "card number leaked")
	assert.False(t, bytes.Contains(blob, []byte(content.CVV)), "cvv leaked")

	// And the client can read it back.
	decrypted, err := crypt.Decrypt(blob, dek)
	require.NoError(t, err)
	got := &Card{}
	require.NoError(t, Unmarshal(decrypted, got))
	assert.Equal(t, content, got)
}
