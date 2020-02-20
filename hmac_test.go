package gojwt

import (
	"errors"
	"strings"
	"testing"
)

type customPayload2 struct {
	Subject  string `json:"sub,omitempty"`
	Name     string `json:"name,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
}

func (t *customPayload2) Valid() error {
	if t.IsValidName(t.Name) == false {
		return errors.New("Invalid Name")
	}
	return nil
}

func (t *customPayload2) IsValidName(name string) bool {
	if name != "John Doe" {
		return false
	}
	return true
}

type customPayload3 struct {
	Subject  string `json:"sub,omitempty"`
	Name     string `json:"name,omitempty"`
	Admin    bool   `json:"admin,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
}

func (t *customPayload3) Valid() error { return nil }

type testDataHMAC struct {
	secret    []byte
	method    uint
	payload   Claims
	wantValue string
	wantError error
}

var testVectorHMAC = []testDataHMAC{
	{
		secret: []byte("testing"),
		method: HS256,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.UJFGOSLW3ar5q9qU
		k8IOFrOYUsdL8pd9je3yV2Kp-9g
		`,
		wantError: nil,
	},
	{
		secret: []byte("AnotherSecretTest"),
		method: HS256,
		payload: &customPayload2{
			Subject:  "1234567890",
			Name:     "John Doe",
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Kjk6myHYtFobVlM2
		03An43P8T59pT2EMIh6wWlGrD2E
		`,
		wantError: nil,
	},
	{
		secret: []byte("--secret--*199200"),
		method: HS256,
		payload: &customPayload2{
			Subject:  "1234567890",
			Name:     "John Doe",
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xLZaN0z9U3gK6Xw3
		w1vRV9BeHyIERKFNNLMY82RXzfw
		`,
		wantError: nil,
	},
	{
		secret: []byte("notSoSecret67"),
		method: HS256,
		payload: &customPayload2{
			Subject:  "123456",
			Name:     "John Doe",
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJuYW1
		lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.1ybBPz6tft936n0o7fj7wh
		beAljiv9_pgSw-SOfMtBM
		`,
		wantError: nil,
	},
	{
		secret: []byte("notSoSecret67"),
		method: HS256,
		payload: &customPayload2{
			Subject:  "123456",
			Name:     "John Doe2",
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJuYW1
		lIjoiSm9obiBEb2UyIiwiaWF0IjoxNTE2MjM5MDIyfQ.2F2Z-89hOhEOxNH6ubjJ
		01TOAnQExm313ziPq-D4bmY
		`,
		wantError: errors.New("Invalid Name"),
	},
	{
		secret: []byte("your-512-bit-secret"),
		method: HS512,
		payload: &customPayload3{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64z
		Dl2ofkT8F6jBt_K4riU-fPg
		`,
		wantError: nil,
	},
}

func init() {
	var tmp []testDataHMAC
	r := strings.NewReplacer("\n", "", "\t", "")
	for _, data := range testVectorHMAC {
		data.wantValue = r.Replace(data.wantValue)
		tmp = append(tmp, data)
	}
	testVectorHMAC = tmp
}

func TestHMACSign(t *testing.T) {

	for i, data := range testVectorHMAC {

		token := NewToken(data.method, data.payload)
		if got := token.Validate(); got != nil && got.Error() != data.wantError.Error() {
			t.Errorf("[%d] got '%v' want '%v'", i, got, data.wantError)
		}
		if err := token.Sign(data.secret); err != nil {
			t.Error(err)
		}
		if token.Value != data.wantValue {
			t.Errorf("[%d] got '%v' want '%v'", i, token.Value, data.wantValue)
		}
	}

}

func TestHMACVerify(t *testing.T) {

	for i, data := range testVectorHMAC {

		token := NewToken(data.method, data.payload)

		if err := token.Parse(data.wantValue, false); err != nil {
			t.Errorf("[%d] err '%v' val '%v'", i, err, data.wantValue)
		}

		if err := token.Verify(data.secret); err != nil {
			t.Error(err)
		}
	}

}
