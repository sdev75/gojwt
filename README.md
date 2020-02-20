# gojwt

Another JWT implementation written in Go. The package implements HS256, RS256, 
PS256 as well as others. The library can be further extended to support 
additional signing algorithms such as Elliptic Curve ECSDA. Inspired by JWT-GO.

Signing algorithms implemented:
* HMAC-SHA 256 (HS256)
* HMAC-SHA 512 (HS512)
* RSA-SHA256 (RS256)
* RSA-SHA512 (RS512)
* RSA-PSS-SHA256 (PS256)

# Algorithms
## HS vs RS
The main difference between the HMAC-SHA256 and RSA-SHA256 is that the HMAC-SHA256 requires the secret to be shared on every application in order to sign *and verify* the JWT. Thus possibly exposing your secret with one or more parties. 
RSA-SHA256 will use an RSA keypair allowing to verify the JWT without exposing the secret (private key) to all parties.

The PS (RSASSA-PSS) signature algorithm is an improved version of the PKCS#1 v1.5. PSS takes an input with a random number salt.

# Basic usage
```go
token := gojwt.NewToken(gojwt.HS256, &IanaClaims{})
```

Instantiation of the token struct is quite fast:
```
BenchmarkTokenInst-8   	293792617	         4.10 ns/op	       0 B/op	       0 allocs/op
```

# Custom payloads
Custom payloads / claims must implement the Payload interface
```go
type MyPayload struct {
	CustomField  string `json:"customfield,omitempty"`
}

func (t *MyPayload) Valid() error {
	return nil
}
```

# Key generation using OpenSSL
Private and public keys can be generated using OpenSSL as shown below.
```bash
# private key without password
openssl genrsa -out rsa.key 4096

# private key with password
openssl genrsa -des3 -passout pass:mysecret -out rsa.key 4096

# extract public key from private keypair
openssl rsa -in rsa.key -pubout > rsa.pub
```

# More examples
More examples will be added in the future.
