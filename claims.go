package gojwt

import (
	"fmt"
	"time"
)

type Claims interface {
	Valid() error
}

// None of the claims
// defined below are intended to be mandatory to use or implement in all
// cases, but rather they provide a starting point for a set of useful,
// interoperable claims. See ref: https://tools.ietf.org/html/rfc7519
type IanaClaims struct {

	// The "iss" (issuer) claim identifies the principal that issued the JWT
	Issuer string `json:"iss,omitempty"`

	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT
	Subject string `json:"sub,omitempty"`

	// The "aud" (audience) claim identifies the recipients that the
	// JWT is intended for.
	Audience string `json:"aud,omitempty"`

	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing.
	ExpiresAt int64 `json:"exp,omitempty"`

	// The "nbf" (not before) claim identifies the time before which the JWT
	// MUST NOT be accepted for processing.
	NotBefore int64 `json:"nbf,omitempty"`

	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued.
	IssuedAt int64 `json:"iat,omitempty"`

	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	Jti string `json:"jti,omitempty"`
}

func (c *IanaClaims) VerifyIssuer(cmp string) bool {
	return VerifyIss(c.Issuer, cmp)
}

func (c *IanaClaims) VerifyAudience(cmp string) bool {
	return VerifyAud(c.Audience, cmp)
}

func (c *IanaClaims) VerifyExpiresAt(cmp int64) bool {
	return VerifyExp(c.ExpiresAt, cmp)
}

func (c *IanaClaims) VerifyNotBefore(cmp int64) bool {
	return VerifyNbf(c.NotBefore, cmp)
}

func (c *IanaClaims) VerifyIssuedAt(cmp int64) bool {
	return VerifyIat(c.IssuedAt, cmp)
}

func (c IanaClaims) Valid() error {
	err := new(TokenError)
	now := time.Now().Unix()

	if c.VerifyExpiresAt(now) == false {
		//delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		err.Text = fmt.Errorf("Token expired")
		err.Flags |= ErrorInvalidExpiration
	}

	if c.VerifyNotBefore(now) == false {
		err.Text = fmt.Errorf("Token used before validity")
		err.Flags |= ErrorInvalidNotBefore
	}

	if c.VerifyIssuedAt(now) == false {
		err.Text = fmt.Errorf("Token used before issued")
		err.Flags |= ErrorInvalidIssuedAt
	}

	if err.Flags != 0 {
		return err
	}

	return nil
}
