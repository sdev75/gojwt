package gojwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func ParseRSAPrivateKey(key []byte, password []byte) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}

	if len(password) != 0 {
		der, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}
		pkey, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, err
		}
		return pkey, nil
	}

	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pkey, nil

}

func ParseRSAPublicKey(key []byte) (*rsa.PublicKey, error) {

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if pkey, ok := pub.(*rsa.PublicKey); ok {
		return pkey, nil
	}

	return nil, errors.New("Unknown type of public key")
}

func ParseRSAPrivateKeyFromFile(filename string, password []byte) (*rsa.PrivateKey, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParseRSAPrivateKey(buf, password)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func ParseRSAPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParseRSAPublicKey(buf)
	if err != nil {
		return nil, err
	}

	return key, nil
}
