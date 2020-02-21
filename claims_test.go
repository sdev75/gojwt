package gojwt

import (
	"testing"
	"time"
)

func TestIanaClaimsExpired(t *testing.T) {
	claims := new(IanaClaims)
	claims.ExpiresAt = time.Now().Add(time.Second * -1).Unix()
	claims.IssuedAt = time.Now().Add(time.Second * 1).Unix()
	claims.NotBefore = time.Now().Add(time.Second * 1).Unix()

	err := claims.Valid()

	got := err.(*TokenError).Flags & ErrorInvalidExpiration
	if got != ErrorInvalidExpiration {
		t.Errorf("got '%v' want '%v'", got, ErrorInvalidExpiration)
	}

	got = err.(*TokenError).Flags & ErrorInvalidIssuedAt
	if got != ErrorInvalidIssuedAt {
		t.Errorf("got '%v' want '%v'", got, ErrorInvalidIssuedAt)
	}

	got = err.(*TokenError).Flags & ErrorInvalidNotBefore
	if got != ErrorInvalidNotBefore {
		t.Errorf("got '%v' want '%v'", got, ErrorInvalidNotBefore)
	}
}

func TestIanaClaimsValid(t *testing.T) {
	claims := new(IanaClaims)

	if got := claims.Valid(); got != nil {
		t.Errorf("got '%v' want '%v'", got, nil)
	}
}

func TestIanaClaimsNotExpired(t *testing.T) {
	claims := new(IanaClaims)
	claims.ExpiresAt = time.Now().Add(time.Second * 1).Unix()

	if got := claims.Valid(); got != nil {
		t.Errorf("got '%v' want '%v'", got, nil)
	}
}

func TestIanaClaimsNotBeforeInvalid(t *testing.T) {
	claims := new(IanaClaims)
	claims.NotBefore = time.Now().Add(time.Second * 1).Unix()

	want := false
	if got := claims.VerifyNotBefore(time.Now().Unix()); got != want {
		t.Errorf("got '%v' want '%v'", got, want)
	}
}

func TestIanaClaimsNotBeforeValid(t *testing.T) {
	claims := new(IanaClaims)
	claims.NotBefore = time.Now().Add(time.Second * -1).Unix()

	want := true
	if got := claims.VerifyNotBefore(time.Now().Unix()); got != want {
		t.Errorf("got '%v' want '%v'", got, want)
	}
}

func TestParseClaimV1(t *testing.T) {
	claims := ClaimsV1{
		CustomField: "Testing",
	}

	err := claims.Valid()
	if err.Error() != "CustomField mismatch" {
		t.Error(err)
	}

}
