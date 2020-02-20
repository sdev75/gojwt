package gojwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func Parse(token *Token, tokenString string, validate bool) error {

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return errors.New("The token does not have 3 segments")
	}

	seg, err := DecodeSegment(parts[0])
	if err != nil {
		return fmt.Errorf("Invalid algorithm and token type segment: %v", err)
	}
	if err = json.Unmarshal(seg, &token.Header); err != nil {
		return fmt.Errorf("Unable to unmarshal header json data: %v", err)
	}

	seg, err = DecodeSegment(parts[1])
	if err != nil {
		return fmt.Errorf("Invalid payload segment: %v", err)
	}

	dec := json.NewDecoder(bytes.NewBuffer(seg))
	dec.UseNumber()
	err = dec.Decode(&token.Payload)
	if err != nil {
		return fmt.Errorf("Unable to decode payload data: %v", err)
	}

	var method string
	method, ok := token.Header["alg"].(string)
	if ok != true {
		return errors.New("Invalid signing algorithm found in header")
	}
	switch method {
	case "HS256":
	case "HS512":
	case "RS256":
	case "RS512":
	case "PS256":
	default:
		return errors.New("Unsupported signing algorithm in the header")
	}

	if validate {
		err = token.Validate()
		if err != nil {
			return err
		}
	}

	token.Signature = parts[2]
	token.HeaderPayload = strings.Join(parts[:2], ".")
	token.Value = tokenString
	return nil
}
