package gojwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
)

type SignMethodRSAPSS struct {
	Hash crypto.Hash
}

func (m SignMethodRSAPSS) Verify(signingString string, signature string, key interface{}) error {
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}
	h := m.Hash.New()
	h.Write([]byte(signingString))

	return rsa.VerifyPSS(key.(*rsa.PublicKey), m.Hash,
		h.Sum(nil), sig, &rsa.PSSOptions{
			Hash:       m.Hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
}

func (m SignMethodRSAPSS) Sign(signinString string, key interface{}) (string, error) {
	h := m.Hash.New()
	h.Write([]byte(signinString))

	sig, err := rsa.SignPSS(
		rand.Reader, key.(*rsa.PrivateKey), m.Hash, h.Sum(nil), &rsa.PSSOptions{
			Hash:       m.Hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	if err != nil {
		return "", err
	}

	res := strings.TrimRight(
		base64.URLEncoding.EncodeToString(sig), "=")
	return res, nil
}

func (m SignMethodRSAPSS) Alg() crypto.Hash {
	return m.Hash
}
