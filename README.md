# gojwt

Package gojwt provides JWT implementation using HMAC SHA256 signing method.

This package does not follow all implementation requirements imposed by rfc7519.
The JSON Web Signature ("JWS") is MACed using the HMAC SHA-256 ("HS256") 
algorithm. Further algorithms might be implemented in the future...

Package inspired by jwt-go