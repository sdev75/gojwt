package gojwt

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strings"
)

type SignMethodHMAC struct {
	Hash crypto.Hash
}

func (m SignMethodHMAC) Verify(signingString string, signature string, key interface{}) error {
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}

	h := hmac.New(m.Hash.New, key.([]byte))
	h.Write([]byte(signingString))
	if !hmac.Equal(sig, h.Sum(nil)) {
		return errors.New("Signature mismatch")
	}

	return nil
}

func (m SignMethodHMAC) Sign(signinString string, key interface{}) (string, error) {
	h := hmac.New(m.Hash.New, key.([]byte))
	h.Write([]byte(signinString))
	res := strings.TrimRight(
		base64.URLEncoding.EncodeToString(h.Sum(nil)), "=")
	return res, nil
}

func (m SignMethodHMAC) Alg() crypto.Hash {
	return m.Hash
}
