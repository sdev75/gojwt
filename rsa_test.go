package gojwt

import (
	"errors"
	"strings"
	"testing"
)

type customPayload struct {
	Subject  string `json:"sub,omitempty"`
	Name     string `json:"name,omitempty"`
	Admin    bool   `json:"admin,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
}

func (t *customPayload) Valid() error {
	if t.IsValidName(t.Name) == false {
		return errors.New("Invalid Name")
	}
	return nil
}

func (t *customPayload) IsValidName(name string) bool {
	if name != "John Doe" {
		return false
	}
	return true
}

type testDataRSA struct {
	pemPassword []byte
	pemData     string
	method      uint
	payload     Claims
	wantValue   string
	wantError   error
}

var testVectorRSA = []testDataRSA{
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN RSA PRIVATE KEY-----
		MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
		kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
		m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
		NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
		3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
		QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
		kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
		amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
		+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
		D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
		0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
		lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
		hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
		bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
		+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
		BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
		2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
		QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
		5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
		Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
		NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
		8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
		3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
		y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
		jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
		-----END RSA PRIVATE KEY-----
		`,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		method: RS256,
		wantValue: `
		eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF
		1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcE
		EbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n
		3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_c
		m-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6Y
		C1aSfLQxeNe8djT9YjpvRZA
		`,
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
		vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
		aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
		tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
		e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
		V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
		MwIDAQAB
		-----END PUBLIC KEY-----
		`,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		method: RS256,
		wantValue: `
		eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF
		1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcE
		EbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n
		3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_c
		m-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6Y
		C1aSfLQxeNe8djT9YjpvRZA
		`,
		wantError: nil,
	},
	{
		pemPassword: []byte("mysecret"),
		pemData: `
		-----BEGIN RSA PRIVATE KEY-----
		Proc-Type: 4,ENCRYPTED
		DEK-Info: DES-EDE3-CBC,9E81F663414B6882

		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
		-----END RSA PRIVATE KEY-----
		`,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		method: RS256,
		wantValue: `
		eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.Lv4IGP0ZMaD74o2QUXq_JePeWul0q7NzGNgg0OIHjOiH5u4QtwTRKVvMnwju1E9
		OduTu_ELeD71YAbmc41_DysPXzqtZBkuXH_YM5RSmtrzla0756j0Ti0Db8uGjNWZ
		7TA80sxblf6OOlRxLEn2tnOcBt6cRv7iRoUqZFeU9P-9HI6mEp6G8JZAm7oque6x
		TjPM7b537NKWFNnfYPydexBgS_1PWMRi3lDECBA8ivyesBpbuym-88rLZcfqo76Z
		ISkdyros2UAEPh9UR5xT78TDedmCKqaAG1fP8B0exqYgJsZV5kmoEpgCdFxkH5yF
		2rzpPtSqw6V4ySK-9F-eKhgbIVbMCa8NUMZxhFhgu-ziZWvSKM03ubTjll4-W2nf
		1hNXJ10HY0OSRQaaiK31BR9Q1luQbRr4Aprw8ThfYx9gpKfqQWWL8mCA7kyguvSB
		5PuSa0xSYe16OqAnlvh1j5R_wGi5NHD4q_I_xWJ3EGz6Ewxe3Dixq-dL2xZ_VUAd
		UUF4X4q11RazfyDIxhBvAGDucweSfLKJxGlH0dszHBOATiAygOZNcSuyy8m4K3vC
		fjogBpS-cEhheR4OqSP5gHsp_eMUAye2Gcvi8xRixgOhSCk25RDEDKtDJ29TZjKG
		oOhiFgE7M7MJlH70hX8koY8Hke2mvoYhxao1hs_VJSqQ
		`,
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN PUBLIC KEY-----
		MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4Qa5VsGFc8u1nfCcqSyw
		MeHoLU4S3Dft5Tde2w9ItwoX6BDXGf/S07wNTAOyMvZVgGPorgf86/QemmwKSe04
		eDYZ7olBeUjCyuVzvWs1YITNoIes+59+Gn39yup5i2s67jp1LRdaqdHH1+8xcJud
		tMfuhong9NqpRVvKAqySBiJBdvBpCc/qygtGfC7LIELWBtKUt2Soc+UQCVZWG38E
		bUSLyokT2gxDNhsSuMnzjSTWVzlsjwOj5mlBc1S2QCsk+w+PFXS91C1cW31/clUT
		qNqz87d4dlqnNGTufgC+77dXnHxhH1nIJWMYc7tVQkK0WJdKzTltK4uOUEIAP0Wz
		tazdracrbcbj0UtQnK5D9wwREk/3GfKFLLhJ/HFAbexUD37jsAfdtP3hmVRLMuy7
		2LtlYTSKkYjgEH9G8dNgn3yQkqI3pC6yRrovhqv1gV4Je5WwVrcU+9w3XtAW4fNQ
		2r7KwfCQUk+oPlI7Gg8zp6oT0aXF+siewnUUz5rQSNxpCaGugIkOzOKkVbwyeqGn
		YvHpk9MZ+Esan7+RvIZgLYCvRzalYYFuBW2Wc1H1EkcYYVMAPYVbqsroRPddJLdv
		WaBywXv2GLodhJw5K30WqND1o3QkKFbRe642WiOaN/RxFeMHajWZWJVynZTCWngI
		o0LKcTkkx7zSrsphrJvvtIUCAwEAAQ==
		-----END PUBLIC KEY-----		
		`,
		method: RS256,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.Lv4IGP0ZMaD74o2QUXq_JePeWul0q7NzGNgg0OIHjOiH5u4QtwTRKVvMnwju1E9
		OduTu_ELeD71YAbmc41_DysPXzqtZBkuXH_YM5RSmtrzla0756j0Ti0Db8uGjNWZ
		7TA80sxblf6OOlRxLEn2tnOcBt6cRv7iRoUqZFeU9P-9HI6mEp6G8JZAm7oque6x
		TjPM7b537NKWFNnfYPydexBgS_1PWMRi3lDECBA8ivyesBpbuym-88rLZcfqo76Z
		ISkdyros2UAEPh9UR5xT78TDedmCKqaAG1fP8B0exqYgJsZV5kmoEpgCdFxkH5yF
		2rzpPtSqw6V4ySK-9F-eKhgbIVbMCa8NUMZxhFhgu-ziZWvSKM03ubTjll4-W2nf
		1hNXJ10HY0OSRQaaiK31BR9Q1luQbRr4Aprw8ThfYx9gpKfqQWWL8mCA7kyguvSB
		5PuSa0xSYe16OqAnlvh1j5R_wGi5NHD4q_I_xWJ3EGz6Ewxe3Dixq-dL2xZ_VUAd
		UUF4X4q11RazfyDIxhBvAGDucweSfLKJxGlH0dszHBOATiAygOZNcSuyy8m4K3vC
		fjogBpS-cEhheR4OqSP5gHsp_eMUAye2Gcvi8xRixgOhSCk25RDEDKtDJ29TZjKG
		oOhiFgE7M7MJlH70hX8koY8Hke2mvoYhxao1hs_VJSqQ
		`,
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN RSA PRIVATE KEY-----
		MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
		kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
		m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
		NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
		3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
		QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
		kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
		amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
		+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
		D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
		0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
		lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
		hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
		bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
		+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
		BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
		2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
		QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
		5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
		Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
		NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
		8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
		3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
		y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
		jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
		-----END RSA PRIVATE KEY-----
		`,
		method: RS512,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC
		7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYo
		yfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704h
		IS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9i
		tZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf
		77ejqX_CBAqkNdH1Zebn93A
		`,
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
		vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
		aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
		tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
		e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
		V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
		MwIDAQAB
		-----END PUBLIC KEY-----
		`,
		method: RS512,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC
		7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYo
		yfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704h
		IS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9i
		tZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf
		77ejqX_CBAqkNdH1Zebn93A
		`,
		wantError: nil,
	},
}

var testVectorRSAPSS = []testDataRSA{
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN RSA PRIVATE KEY-----
		MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
		kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
		m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
		NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
		3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
		QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
		kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
		amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
		+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
		D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
		0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
		lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
		hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
		bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
		+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
		BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
		2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
		QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
		5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
		Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
		NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
		8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
		3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
		y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
		jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
		-----END RSA PRIVATE KEY-----
		`,
		method: PS256,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: "",
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
		vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
		aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
		tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
		e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
		V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
		MwIDAQAB
		-----END PUBLIC KEY-----
		`,
		method: PS256,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.hZnl5amPk_I3tb4O-Otci_5XZdVWhPlFyVRvcqSwnDo_srcysDvhhKOD01DigPK
		1lJvTSTolyUgKGtpLqMfRDXQlekRsF4XhAjYZTmcynf-C-6wO5EI4wYewLNKFGGJ
		zHAknMgotJFjDi_NCVSjHsW3a10nTao1lB82FRS305T226Q0VqNVJVWhE4G0JQvi
		2TssRtCxYTqzXVt22iDKkXeZJARZ1paXHGV5Kd1CljcZtkNZYIGcwnj65gvuCwoh
		bkIxAnhZMJXCLaVvHqv9l-AAUV7esZvkQR1IpwBAiDQJh4qxPjFGylyXrHMqh5Nl
		T_pWL2ZoULWTg_TJjMO9TuQ
		`,
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN RSA PRIVATE KEY-----
		MIIJKQIBAAKCAgEA0wpigMK8E1rpQ1qNguoAfkucaoy3tfjSkJ05rOVa0xL27ZM6
		andOo4dncA4pdxU+YKdlwkmTMYhiRIzRxDE5Wy3yuejt4A8RpfiVqp/E5C875R3K
		CeT4JGydv81WjK8Ec5NEXzwptsEuIQHsTEmXWYwXVVJ+hVkm7/clUxMQwO9xMvk7
		9z8O6t04Xaoq7RzQHnXOvHVRwNLbDRGIwDdJVlSIc2lvArJRC4maLXUHggqKeqFd
		vrUhvLw/XyWM80G1qaxyQCvNpFWqJx1gG3CUAsrRnggz0o+GQbS9OuwHCYm82/tA
		PMRl/g1ZenYGckrHt8+sxPk89dKaZemjjibOErP2k0e7l5oprhA0PbGpbxsr4gTd
		7hIJRznrAlxNh2kos2k3OjsWR2gCqoFNuBTCHIICpe/na2CiRXIRtZjetpUx9cKu
		nzvb3zv+UuAA4yd/g0SlEmjFFjBs0YFYUlTBY+8HZu21bd7tX/WHa5lTDj2lZe5W
		UVKClR/2p3reswWJnpEbdMC3nXVs5f0SQFTQXkpJA9sVmplyCXBDxagl1jkMxL8w
		ad0r2aZZhwUiPgZzEdL+QHVeJgkFTxSQWFkl6QiC8TXz+1eqpgRrfzDAhCGUQt+e
		arNA/OnBmbCaPQvQ3NwBvSS4+ZJnLpfaMMJnigNAO/haJa2N2/QzCXUfMOcCAwEA
		AQKCAgEAoUxsoRE1gm2Xn50UT5zeJ6lOsbk/qFu3RESHEnhyBKWYCVjf6wOpHR+e
		lWydkKCx/lmzUt29HLyqrs4afaNJvUDPJfy74uZhjMMEUVavu9/GHYW5J/rTFbPW
		lgQxRHF4K4XBWjC3iTD5Os0nd98/SHfkVZgpj23mbr4szuPhiDT6BgWsKXsOwb+3
		Fw+6o2PERaOxESVyCLigJ8rhBFi9Orh9WgiZiiwT+YeASYIK7P91e+jdp6b1VDVl
		Eim3Iy1z1W0yHY3dLN80n5S6If7XgZLWx7xpL2P3Lz0e7Gv9rPKTYGcWX9uUQKqf
		WxPeNXimUPzvhdUhHJmM3JvIIBvUn9+RmQek5eimwq9v9z7+B+X6Hnf7BvIK5OWM
		kd2h/jERuSua/KPbk6CZb02E2gcWD7vHIFu+Tk5boXT3Jw5nd/3dv8rfRjREHjcO
		487J8REgYGSa+xhlWI9hV9oEhbHjQ6CYdbkGw/v2rmK+G+R2mvHUl6oX3uOnQuio
		B87FJP6DTnEBTd3J/UsHN1sguxYLHw9tet1sp8XPaPbpWTK8MSXjoF57dZp4gIsp
		osvhAYiNcw1GTdCFlGIxw4YrIdp0OcZp7mlv5UpW9g170cxp2UbO39YLFz8KS1fZ
		Ypyonw+zULWc+8zPqJFZa+wO6dLz5c86N6gxDU59NfFGD94b6cECggEBAOjt7xSl
		2VvbjOxgI1RangsOsrmyk6AsC8F52hhW4+kB/IIYwZyHfMFHoFVB9zCwvJJCGs+j
		p/FaQz0dkt2BglZlr7uRVzliFegwwcipvnan/4jmzzKb7PNnW3IPFZa+EClWMuO8
		g9D68Z9U9OE3c8JFJWtd3QD+bWihlaxcP8fybWYqabsepYwvwZJ1kswyyFXmEfUN
		EnsTdeH06WXwUKVEZSEpDYkdCGH5ddk1YYglBHY494ndrCvRkD4jMO00/HrK3jDK
		io5zC1Tkdl42296GFOmkYWdvoLnb3rbz5N+DuuqUqQ1RSv78dDanK2TOJW12Sd3t
		5QrLx2ckIfbWbxECggEBAOfxcg5mZNO92D+rOSrg0URwM8pmcypVkQCoZdbhFQwD
		imv9IyRbgJMPD9HZht+XIWQxNItssMGls2Uvr8WVP0Hi3XKJt30iH59QhYBjmqxb
		f5QQ77bo6dccynE6QP4JRLoMokV1pK/dLbLATj+5uXN/W+GtEKZn5lbV6RRpBSAB
		+4NRn1zEoSpWbbQdeAzfLq7Yn+1LCZ0cesRRQG4NeWHq8604C7NiTWPDz0aAnhe/
		HYd9cR4FJdVchVdoz0hrry4JQAI3a4VLGuSWpYIV1oBIMa1EBh3X6QJltnJhi1Sd
		BcSA88gwu9k7AdI0flQn5gkzaF1z1ufnlMSvJHl4kHcCggEAJyGh4rQiGf5+ZE+a
		X9eBaZYkjHHlvyjnKK/R5fji/QgqZajHDgbs/ION+gTFBFcMtv2IB44U7sUdOq03
		OSNCxET9CuPV5XwG9iUKyS1LJCABG/y6nmP3oMSiZj0GgXaYvHkQv5WyB2/BG+Vn
		5lYsilyXdrwkHsCfnM5YmMY+qNafbmR9ssPpR+3V9UbvTILTiSrHpYV2r1qLmVRN
		yaRfyAP/gVymO3y3Jc6E7+K56edeIoZbf7vP6uSf+PBsjc0zBWYDgerk8B1/r9lZ
		0WYh9fZMmRvWiUwFknPPrKi4sJwu0K384JHhqYi79VqMPbksLIGM003eBrxJWZiG
		ZDOOIQKCAQAEnlkwEjflw3z/34/2250vKLDPUfTvHd8STUgh3D+ICrYB6nt9qNjJ
		lN4yxosZ/q9qiFRMhnCKmpsU47szSwKEdFkGg9mEg15v1LGj2dfloLjMoP20/bRS
		VT9uu8M5i8OzlLbSfUI3Qkc7rPqh6DfaJeoVd1XCioUaq43Fm0W/2mpAtipfNYck
		Ca6LjJ6sWvFaB/Q/TGQ3na6QJDINPvVwzrXleB07iDSUTPzeoYcEYAjdftD20RFs
		yzfYgrzF62cEmqiMor/gWpuBe8J18atgyI88rQMWKwt3wcC9TFXy7GGGBS9ViCrl
		a3hg0CzHzjeVbVGhssHPwlvDAt3OEWmHAoIBAQCAPQG8Eg+KM8JCQXPQNUD0UHjL
		0okFWrIWWlfzcNOjzgR4ucqB0bO7SwZn146YoS1NZMu9JW79c+bJrBASfznfz/Lu
		8wS+L2rHUbnqIn6+iah+YfZlOs9kW9JHWvtXFtY4gPK6FgXSwcJVl63j2Fvn7f+6
		pLaRHe8O9EiGkxCmkMeLPyHqHhsCEI1wIUiaEuJz04UCsA5ovC3AE9U9+1dLsUkI
		5NGpABb3xFDYALlKwOtR2fnHjln+kb6BGuNW6TAlGOJul3GJO07CSUdVRRlS+HOu
		tsrv7TnteC6h4+8WPqEhjzsGxXjdLtNMA1yuS5J7Q6QIBNvfUS4Ku2cGNMWW
		-----END RSA PRIVATE KEY-----
		`,
		method: PS256,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: "",
		wantError: nil,
	},
	{
		pemPassword: nil,
		pemData: `
		-----BEGIN PUBLIC KEY-----
		MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0wpigMK8E1rpQ1qNguoA
		fkucaoy3tfjSkJ05rOVa0xL27ZM6andOo4dncA4pdxU+YKdlwkmTMYhiRIzRxDE5
		Wy3yuejt4A8RpfiVqp/E5C875R3KCeT4JGydv81WjK8Ec5NEXzwptsEuIQHsTEmX
		WYwXVVJ+hVkm7/clUxMQwO9xMvk79z8O6t04Xaoq7RzQHnXOvHVRwNLbDRGIwDdJ
		VlSIc2lvArJRC4maLXUHggqKeqFdvrUhvLw/XyWM80G1qaxyQCvNpFWqJx1gG3CU
		AsrRnggz0o+GQbS9OuwHCYm82/tAPMRl/g1ZenYGckrHt8+sxPk89dKaZemjjibO
		ErP2k0e7l5oprhA0PbGpbxsr4gTd7hIJRznrAlxNh2kos2k3OjsWR2gCqoFNuBTC
		HIICpe/na2CiRXIRtZjetpUx9cKunzvb3zv+UuAA4yd/g0SlEmjFFjBs0YFYUlTB
		Y+8HZu21bd7tX/WHa5lTDj2lZe5WUVKClR/2p3reswWJnpEbdMC3nXVs5f0SQFTQ
		XkpJA9sVmplyCXBDxagl1jkMxL8wad0r2aZZhwUiPgZzEdL+QHVeJgkFTxSQWFkl
		6QiC8TXz+1eqpgRrfzDAhCGUQt+earNA/OnBmbCaPQvQ3NwBvSS4+ZJnLpfaMMJn
		igNAO/haJa2N2/QzCXUfMOcCAwEAAQ==
		-----END PUBLIC KEY-----		
		`,
		method: PS256,
		payload: &customPayload{
			Subject:  "1234567890",
			Name:     "John Doe",
			Admin:    true,
			IssuedAt: 1516239022,
		},
		wantValue: `
		eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw
		ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0
		.Rq9OoWuqTkcNjaorpmgLKbjCW3q-M1pRK8BZ8TzM8NReRJ4AJ5h5bhZ1Ppitf4e
		ywNhQqwPXF9NS09KxONB-pr4ZiRMONj_cpuLtHd9JHKMw9-0ampXzla16bO-Mdy2
		9euuFMCwqSLh9QshpKVHuy48VftX58O6MHggxfumTRgqL-Lh3MOIra6BNUdv98do
		K1dzne8FPPsPh_toxEUUIHYidxovRiBKCSpn2eXfexa889gWT9Fc_nzQ4qmChR6X
		A-MHveZylswjRdKeiTnYrlWF1WXEnIC6N0Zyqp_dODfTWMfmhh8Vt0rPT0nK96HG
		MN2GZPiaXuqI7GmVCU0gEPhQ4f8Fe2DbNVsgx9shzEn9RjT-F-xUkg3hYXUy-vPx
		AOH2e44Gq6jPIogDeXgFj3zNc-mqk1d4MzMQKc-NHNM-l3pnsgdZbcxb-0u30AJW
		9_iGwvZ3pnrhGOouHn9cBvxcwyy2JsFQOvSCF63C8ES4W6APMijt51n_M7dAyQXp
		8A7MMY0ZkQtS1SuDtC0yKtmjOiUmx4vnP8lBlmkqEahfqnuWBtFMg8D0kBraCa01
		yBq4Yqjsd8EGihihN9JpyBMJo6oVRX2SoKX0ve1upYf92ePD5zD0kmADMipNEVJt
		pvCHXB6Hh0pujikHnfqH37aDON21mc1SMsJSnmX-8cGo
		`,
		wantError: nil,
	},
}

func init() {
	var tmp []testDataRSA
	r1 := strings.NewReplacer("\t", "")
	r2 := strings.NewReplacer("\n", "", "\t", "")
	for _, data := range testVectorRSA {
		data.pemData = r1.Replace(data.pemData)
		data.wantValue = r2.Replace(data.wantValue)
		tmp = append(tmp, data)
	}
	testVectorRSA = tmp

	tmp = nil
	for _, data := range testVectorRSAPSS {
		data.pemData = r1.Replace(data.pemData)
		data.wantValue = r2.Replace(data.wantValue)
		tmp = append(tmp, data)
	}
	testVectorRSAPSS = tmp
}

func TestRSAPrivateWithPassword(t *testing.T) {
	data := testVectorRSA[2]
	key, err := ParseRSAPrivateKey([]byte(data.pemData), data.pemPassword)
	if err != nil {
		t.Error(err)
	}

	token := NewToken(RS256, data.payload)

	if err := token.Sign(key); err != nil {
		t.Error(err)
	}
}

func TestRSA(t *testing.T) {

	for i, data := range testVectorRSA {

		if strings.Contains(data.pemData, "PRIVATE") {
			key, err := ParseRSAPrivateKey([]byte(data.pemData), data.pemPassword)
			if err != nil {
				t.Error(err)
			}

			token := NewToken(data.method, data.payload)
			if got := token.Validate(); got != data.wantError {
				t.Errorf("[%d] got '%v' want '%v'", i, got, data.wantError)
			}

			if err := token.Sign(key); err != nil {
				t.Errorf("[%d] %v", i, err)
			}

			if token.Value != data.wantValue {
				t.Errorf("[%d] got '%v' want '%v'", i, token.Value, data.wantValue)
			}
			continue
		}

		key, err := ParseRSAPublicKey([]byte(data.pemData))
		if err != nil {
			t.Error(err)
		}

		token := NewToken(data.method, &customPayload{})
		if err := token.Parse(data.wantValue, true); err != nil {
			t.Errorf("[%d] %v", i, err)
		}

		if err := token.Verify(key); err != nil {
			t.Errorf("[%d] %v", i, err)
		}
	}
}

func TestRSAPSS(t *testing.T) {
	for i, data := range testVectorRSAPSS {

		if strings.Contains(data.pemData, "PRIVATE") {

			key, err := ParseRSAPrivateKey([]byte(data.pemData), data.pemPassword)
			if err != nil {
				t.Error(err)
			}

			token := NewToken(data.method, data.payload)
			if got := token.Validate(); got != data.wantError {
				t.Errorf("[%d] got '%v' want '%v'", i, got, data.wantError)
			}

			if err := token.Sign(key); err != nil {
				t.Errorf("[%d] %v", i, err)
			}

			continue
		}

		key, err := ParseRSAPublicKey([]byte(data.pemData))
		if err != nil {
			t.Error(err)
		}

		token := NewToken(data.method, &customPayload{})
		if err := token.Parse(data.wantValue, true); err != nil {
			t.Errorf("[%d] %v", i, err)
		}

		if err := token.Verify(key); err != nil {
			t.Errorf("[%d] %v", i, err)
		}
	}
}
