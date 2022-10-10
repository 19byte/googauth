# googauth
Impl the Google Authenticator function requires both server-side and client-side support. The server is responsible for key generation and verifying whether the one-time password is correct


## install

```go
go get github.com/19byte/googauth
```

## production key

```go
func Example() {
	secret := googauth.NewTOTPSecret()
	qr := googauth.TOTPQrString("example", "goog", secret)
	fmt.Println(qr)
}
```


## verify

```go
func Example() {
	flag := googauth.VerifyPasscode("7GROVQXRQTC5R2DGK4HHJDLQUM", "289314")
}
```