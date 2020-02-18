package gojwt

const (
	ErrorInvalidToken      uint32 = 1 << iota
	ErrorInvalidIssuer            // "iss" (Issuer)
	ErrorInvalidAudience          // "aud" (Audience)
	ErrorInvalidExpiration        // "exp" (Expiration Time)
	ErrorInvalidNotBefore         // "nbf" (Not Before)
	ErrorInvalidIssuedAt          // "iat" (Issued At)
	ErrorInvalidJti               // "jti" (JWT ID)
	ErrorInvalidClaim             // Generic error
	ErrorIvalidSignature          // Invalid signature
)

type TokenError struct {
	Text  error
	Flags uint32
}

func (e *TokenError) Error() string {
	return e.Text.Error()
}
