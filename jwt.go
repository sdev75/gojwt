package gojwt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Token struct {
	Value     string
	Method    crypto.Hash
	Header    map[string]interface{}
	Claims    Claims
	Signature string
}

func (t *Token) Sign(signingKey []byte) error {

	var b []byte
	var err error
	parts := make([]string, 3)

	b, err = json.Marshal(t.Header)
	if err != nil {
		return err
	}

	parts[0] = strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")

	b, err = json.Marshal(t.Claims)
	if err != nil {
		return err
	}

	parts[1] = strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")

	jwt := strings.Join(parts, ".")
	h := hmac.New(t.Method.New, signingKey)
	h.Write([]byte(jwt[:len(jwt)-1]))
	t.Signature = strings.TrimRight(
		base64.URLEncoding.EncodeToString(h.Sum(nil)), "=")

	parts[2] = t.Signature
	t.Value = strings.Join(parts, ".")
	return nil
}

func (t *Token) Validate() error {
	err := t.Claims.Valid()
	if err != nil {
		return err
	}
	return nil
}
