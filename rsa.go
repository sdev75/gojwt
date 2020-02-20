package gojwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
)

type SignMethodRSA struct {
	Hash crypto.Hash
}

func (m SignMethodRSA) Verify(signingString string, signature string, key interface{}) error {
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}
	h := m.Hash.New()
	h.Write([]byte(signingString))
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), m.Hash, h.Sum(nil), sig)
}

func (m SignMethodRSA) Sign(signinString string, key interface{}) (string, error) {
	h := m.Hash.New()
	h.Write([]byte(signinString))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), m.Hash, h.Sum(nil))
	if err != nil {
		return "", err
	}

	res := strings.TrimRight(
		base64.URLEncoding.EncodeToString(sig), "=")
	return res, nil
}

func (m SignMethodRSA) Alg() crypto.Hash {
	return m.Hash
}
