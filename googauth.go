package googauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// gaEncoding is a google authenticator encoder for encoding and decoding an arbitrary
// string value in base32 according to RFC 3548. The padding specified in RFC 3548
// section 2.2 is not required and should be omitted.
var gaEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// VerifyPasscode validates the user provided code.
func VerifyPasscode(secret, code string) bool {
	key, err := gaEncoding.DecodeString(secret)
	if err != nil {
		// Reports code mismatch if fails to decoding secret.
		return false
	}
	// 30 seconds by default that a TOTP code will be valid for.
	return calculateTOTP(key, time.Now().Unix()/30) == code
}

// NewTOTPSecret returns a underlying base32 encoded secret. This should only be displayed
// the first time a user enables 2FA, and should be transmitted over a secure connection.
// Useful for supporting TOTP clients that don't support QR scanning.
func NewTOTPSecret() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return strings.ToUpper(gaEncoding.EncodeToString(b))
}

//TOTPQrString is the QR code string of the QR code that ccaned by google authenticator.
func TOTPQrString(label, issuer, secret string) (qr string) {
	return fmt.Sprintf(`otpauth://totp/%s?issuer=%s&secret=%s`,
		url.QueryEscape(label),
		url.QueryEscape(issuer),
		secret,
	)
}

// calculateTOTP is a Private function which calculates the OTP token base
// on the given secret key and counter.
func calculateTOTP(key []byte, counter int64) string {
	//RFC 6238 & SHA1.
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	// 1. take the last digit of the hash value as the offset.
	// 2. convert the first 4 bytes from offset of hash value to an integer.
	// 3. remove the most significant bit and set the first bit to zero.
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF // 0x7FFFFFFF == 2^31

	// Take the last 6 digits of a one-time passcode to display to the user.
	return fmt.Sprintf("%06d", v%1000000)
}
