package gojwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Token struct {
	Value         string
	Method        SignMethod
	Header        map[string]interface{}
	Payload       Claims
	Signature     string
	HeaderPayload string
}

func NewToken(id uint, claims Claims) *Token {
	return &Token{
		Method:  SignMethodTable[id].Method,
		Header:  SignMethodTable[id].Header,
		Payload: claims,
	}
}

func (t *Token) Build() error {
	var b []byte
	var err error
	parts := make([]string, 2)

	b, err = json.Marshal(t.Header)
	if err != nil {
		return err
	}

	parts[0] = strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")

	b, err = json.Marshal(t.Payload)
	if err != nil {
		return err
	}

	parts[1] = strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")

	t.HeaderPayload = strings.Join(parts, ".")
	//t.JWT = jwt[:len(jwt)-1]
	return nil
}

func (t *Token) Parse(tokenString string, validate bool) error {
	return Parse(t, tokenString, validate)
}

func (t *Token) Sign(key interface{}) error {
	var err error

	err = t.Build()
	if err != nil {
		return err
	}

	t.Signature, err = t.Method.Sign(t.HeaderPayload, key)
	if err != nil {
		return err
	}

	t.Value = t.HeaderPayload + "." + t.Signature
	return nil
}

func (t *Token) Verify(key interface{}) error {
	return t.Method.Verify(t.HeaderPayload, t.Signature, key)
}

func (t *Token) Validate() error {
	err := t.Payload.Valid()
	if err != nil {
		return err
	}
	return nil
}
