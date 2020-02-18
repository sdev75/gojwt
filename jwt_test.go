package gojwt

import (
	"errors"
	"testing"
)

type CustomClaims struct {
	Subject  string `json:"sub,omitempty"`
	Name     string `json:"name,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
}

func (c *CustomClaims) IsValidName(name string) bool {
	if name != "John Doe" {
		return false
	}
	return true
}

var (
	ErrInvalidName = errors.New("Invalid Name")
)

func (c *CustomClaims) Valid() error {
	if c.IsValidName(c.Name) == false {
		return ErrInvalidName
	}
	return nil
}

var TestTable = []struct {
	Secret        []byte
	Claims        CustomClaims
	ExpectedValue string
	ExpectedError error
}{
	{
		[]byte("testing"),
		CustomClaims{Subject: "1234567890", Name: "John Doe", IssuedAt: 1516239022},
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
			"UJFGOSLW3ar5q9qUk8IOFrOYUsdL8pd9je3yV2Kp-9g",
		nil,
	},
	{
		[]byte("AnotherSecretTest"),
		CustomClaims{Subject: "1234567890", Name: "John Doe", IssuedAt: 1516239022},
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
			"Kjk6myHYtFobVlM203An43P8T59pT2EMIh6wWlGrD2E",
		nil,
	},
	{
		[]byte("--secret--*199200"),
		CustomClaims{Subject: "1234567890", Name: "John Doe", IssuedAt: 1516239022},
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
			"xLZaN0z9U3gK6Xw3w1vRV9BeHyIERKFNNLMY82RXzfw",
		nil,
	},
	{
		[]byte("notSoSecret67"),
		CustomClaims{Subject: "123456", Name: "John Doe", IssuedAt: 1516239022},
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9." +
			"1ybBPz6tft936n0o7fj7whbeAljiv9_pgSw-SOfMtBM",
		nil,
	},
	{
		[]byte("notSoSecret67"),
		CustomClaims{Subject: "123456", Name: "John Doe2", IssuedAt: 1516239022},
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiSm9obiBEb2UyIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
			"2F2Z-89hOhEOxNH6ubjJ01TOAnQExm313ziPq-D4bmY",
		ErrInvalidName,
	},
}

func TestSigning(t *testing.T) {
	var token *Token
	for k, v := range TestTable {

		token = NewSha256Token(&v.Claims)
		if got := token.Validate(); got != v.ExpectedError {
			t.Errorf("[%d] got '%v' want '%v'", k, got, v.ExpectedError)

		}

		token.Sign(v.Secret)
		if token.Value != v.ExpectedValue {
			t.Errorf("[%d] got '%v' want '%v'", k,
				token.Value, v.ExpectedValue)
		}
	}
}

func TestCustomClaims(t *testing.T) {
	token := NewSha256Token(&CustomClaims{
		Subject:  "1234567890",
		Name:     "John Doe2",
		IssuedAt: 1516239022,
	})

	want := ErrInvalidName
	if got := token.Validate(); got != want {
		t.Errorf("token.Validate() = %q, want %q", got, want)
	}

}

func BenchmarkClaimsValidation(b *testing.B) {
	token := NewSha256Token(&CustomClaims{
		Subject:  "1234567890",
		Name:     "John Doe2",
		IssuedAt: 1516239022,
	})
	for n := 0; n < b.N; n++ {
		token.Validate()
	}
}

func BenchmarkSigning(b *testing.B) {
	token := NewSha256Token(&CustomClaims{
		Subject:  "1234567890",
		Name:     "John Doe2",
		IssuedAt: 1516239022,
	})
	for n := 0; n < b.N; n++ {
		token.Sign([]byte("testing"))
	}
}
