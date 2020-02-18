package gojwt

import (
	"crypto"
)

func NewSha256Token(claims Claims) *Token {
	return &Token{
		Method: crypto.SHA256,
		Header: map[string]interface{}{
			"alg": "HS256",
			"typ": "JWT",
		},
		Claims: claims,
	}
}
