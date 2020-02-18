package gojwt

import "crypto/subtle"

func VerifyExp(exp int64, now int64) bool {
	return now <= exp
}

func VerifyIat(iat int64, now int64) bool {
	return now >= iat
}

func VerifyNbf(nbf int64, now int64) bool {
	return now >= nbf
}

func VerifyAud(iss string, cmp string) bool {
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	}
	return false
}

func VerifyIss(iss string, cmp string) bool {
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	}
	return false
}
