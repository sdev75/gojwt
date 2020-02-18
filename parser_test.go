package gojwt

import (
	"errors"
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

func TestParse(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	token := NewSha256Token(&CustomClaims{})
	if err := token.Parse(tokenString, true); err != nil {
		t.Error(err)
	}
}

func TestParseClaimV1(t *testing.T) {
	claims := ClaimsV1{
		CustomField: "Testing",
	}
	token := NewSha256Token(&claims)
	if err := token.Sign([]byte("testing")); err != nil {
		t.Error(err)
	}

	want := "Testing"
	if got := token.Claims.(*ClaimsV1).CustomField; got != want {
		t.Errorf("got '%v' want '%v'", got, want)
	}

	want = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJDdXN0b21GaWVsZCI6IlRlc3RpbmcifQ." +
		"12erzvB7FF8ds4Q8Hv9IMYGJlYh2uy_pakckYmLldc8"
	if got := token.Value; got != want {
		t.Errorf("got '%v' want '%v'", got, want)
	}

	err := token.Validate()
	if err.Error() != "CustomField mismatch" {
		t.Error(err)
	}

}
