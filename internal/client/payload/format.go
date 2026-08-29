package payload

import (
	"fmt"
	"strings"
)

// maskedCardTail is how many last digits of a card number stay
// visible.
const maskedCardTail = 4

// Format returns the content as text for the terminal. Secret
// values (password, card number, CVV) are hidden unless reveal
// is true.
func Format(content any, reveal bool) string {
	switch v := content.(type) {
	case *LoginPassword:
		return formatLoginPassword(v, reveal)
	case *Text:
		return v.Text
	case *Binary:
		return fmt.Sprintf("file: %s\nsize: %d bytes", v.Filename, len(v.Data))
	case *Card:
		return formatCard(v, reveal)
	default:
		return fmt.Sprintf("%v", content)
	}
}

func formatLoginPassword(v *LoginPassword, reveal bool) string {
	password := "********"
	if reveal {
		password = v.Password
	}
	return fmt.Sprintf("login:    %s\npassword: %s", v.Login, password)
}

func formatCard(v *Card, reveal bool) string {
	number, cvv := v.Number, v.CVV
	if !reveal {
		number = MaskCardNumber(number)
		cvv = "***"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "number: %s\n", number)
	fmt.Fprintf(&b, "holder: %s\n", v.Holder)
	fmt.Fprintf(&b, "expiry: %s\n", v.Expiry)
	fmt.Fprintf(&b, "cvv:    %s", cvv)
	return b.String()
}

// MaskCardNumber hides all digits but the last four.
func MaskCardNumber(number string) string {
	digits := []rune(number)
	if len(digits) <= maskedCardTail {
		return strings.Repeat("*", len(digits))
	}

	masked := strings.Repeat("*", len(digits)-maskedCardTail)
	return masked + string(digits[len(digits)-maskedCardTail:])
}
