package gojwt

import "crypto"

type SignMethodData struct {
	Method SignMethod
	Header map[string]interface{}
}

const (
	HS256 uint = 1 + iota
	HS512
	RS256
	RS512
	PS256
)

var (
	SignMethodTable = []SignMethodData{
		HS256: SignMethodData{
			Method: SignMethodHMAC{Hash: crypto.SHA256},
			Header: map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		},
		HS512: SignMethodData{
			Method: SignMethodHMAC{Hash: crypto.SHA512},
			Header: map[string]interface{}{"alg": "HS512", "typ": "JWT"},
		},
		RS256: SignMethodData{
			Method: SignMethodRSA{Hash: crypto.SHA256},
			Header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		},
		RS512: SignMethodData{
			Method: SignMethodRSA{Hash: crypto.SHA512},
			Header: map[string]interface{}{"alg": "RS512", "typ": "JWT"},
		},
		PS256: SignMethodData{
			Method: SignMethodRSAPSS{Hash: crypto.SHA256},
			Header: map[string]interface{}{"alg": "PS256", "typ": "JWT"},
		},
	}
)

type SignMethod interface {
	Verify(string, string, interface{}) error
	Sign(string, interface{}) (string, error)
	Alg() crypto.Hash
}
