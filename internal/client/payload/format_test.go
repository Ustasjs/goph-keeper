package payload

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormat_hidesSecretsByDefault(t *testing.T) {
	t.Parallel()

	t.Run("login password", func(t *testing.T) {
		t.Parallel()

		content := &LoginPassword{Login: "alice", Password: "s3cret"}

		hidden := Format(content, false)
		assert.Contains(t, hidden, "alice")
		assert.NotContains(t, hidden, "s3cret")

		shown := Format(content, true)
		assert.Contains(t, shown, "s3cret")
	})

	t.Run("card", func(t *testing.T) {
		t.Parallel()

		content := &Card{Number: "4111111111111111", Holder: "ALICE", Expiry: "12/30", CVV: "123"}

		hidden := Format(content, false)
		assert.Contains(t, hidden, "1111", "last four digits stay visible")
		assert.NotContains(t, hidden, content.Number)
		assert.NotContains(t, hidden, "cvv:    123")
		assert.Contains(t, hidden, "ALICE", "holder is not a secret")

		shown := Format(content, true)
		assert.Contains(t, shown, content.Number)
		assert.Contains(t, shown, "123")
	})
}

func TestFormat_textAndBinary(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "my note", Format(&Text{Text: "my note"}, false))

	binary := Format(&Binary{Filename: "scan.pdf", Data: make([]byte, 42)}, false)
	assert.Contains(t, binary, "scan.pdf")
	assert.Contains(t, binary, "42 bytes")
}

func TestMaskCardNumber(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		number string
		want   string
	}{
		{"full number", "4111111111111111", "************1111"},
		{"short number", "1234", "****"},
		{"shorter than tail", "12", "**"},
		{"empty", "", ""},
		{"five digits", "12345", "*2345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, MaskCardNumber(tt.number))
		})
	}
}
