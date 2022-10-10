package googauth

import (
	"fmt"
	"testing"
)

func TestNewTOTPSecret(t *testing.T) {
	secret := NewTOTPSecret()
	fmt.Println(secret)
	qr := TOTPQrString("example", "issuer", secret)
	fmt.Println(qr)
}

func TestVerifyPasscode(t *testing.T) {
	fmt.Println(VerifyPasscode("7GROVQXRQTC5R2DGK4HHJDLQUM", "002892"))
}
