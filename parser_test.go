package gojwt

import (
	"errors"
	"fmt"
	"log"
	"testing"
)

type ClaimsV1 struct {
	CustomField string
}

func (c ClaimsV1) Valid() error {
	if c.CustomField != "expected value" {
		return errors.New("CustomField mismatch")
	}

	return nil
}

type claimsRS struct {
	IanaClaims
	Admin bool `json:"admin,omitempty"`
}

func (c *claimsRS) Valid() error {
	return nil
}

type customClaims struct {
	Subject  string `json:"sub,omitempty"`
	Name     string `json:"name,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
}

func (t *customClaims) Valid() error {
	if t.IsValidName(t.Name) == false {
		return errors.New("Invalid Name")
	}
	return nil
}

func (t *customClaims) IsValidName(name string) bool {
	if name != "John Doe" {
		return false
	}
	return true
}

func ParsingHS256() {}
func ParsingRS256() {}

func ExampleParsingHS256() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	token := NewToken(HS256, &customClaims{})
	token.Parse(jwt, false)
	fmt.Println(token.HeaderPayload)
	fmt.Println(token.Signature)

	// Output:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
	// SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
}

func ExampleParsingRS256() {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0." +
		"POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_" +
		"TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0n" +
		"H3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_" +
		"dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_" +
		"cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxt" +
		"F2pZS6YC1aSfLQxeNe8djT9YjpvRZA"
	token := &Token{Payload: &claimsRS{}}
	err := Parse(token, jwt, false)
	if err != nil {
		log.Print(err)
	}

	fmt.Println(token.HeaderPayload)
	fmt.Println(token.Signature[:len("POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_")])

	// Output:
	// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
	// POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_
}

func TestParseWithoutValidation(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	var token = &Token{Payload: &IanaClaims{}}
	if err := token.Parse(tokenString, false); err != nil {
		t.Error(err)
	}
}

func TestParseAndValidate(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	var token = &Token{Payload: &IanaClaims{}}
	if err := token.Parse(tokenString, true); err != nil {
		t.Error("Token is supposed to be valid...")
	}
}
