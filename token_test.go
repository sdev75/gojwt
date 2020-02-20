package gojwt

import "testing"

func BenchmarkTokenInst(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewToken(HS256, &IanaClaims{})
	}
}

func TestToken(t *testing.T) {
	token := NewToken(HS256, &IanaClaims{})
	token.Validate()
	token.Build()
	token.Parse("", false)
	token.Parse("", true)
}
