package ptpm

var (
	testInvalidKey = []byte(`{}`)
	testValidCK    = []byte(`{
		"kid": "valid-ck",
		"kty": "EC",
		"crv": "P-384",
		"x": "gvvRMqm1w5aHn7sVNA2QUJeOVcedUnmiug6VhU834gzS9k87crVwu9dz7uLOdoQl",
		"y": "7fVF7b6J_6_g6Wu9RuJw8geWxEi5ja9Gp2TSdELm5u2E-M7IF-bsxqcdOj3n1n7N",
		"d": "ODkwMTIzNDU2Nzg5MDEyMz7deMbyLt8g4cjcxozuIoygLLlAeoQ1AfM9TSvxkFHJ"
	}`)
	testValidSK = []byte(`{
		"kid": "valid-pak",
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`)

	testInvalidParsectpmClaims = []byte(`{}`)
	testValidParsectpmClaims   = []byte(`{
		"tpmVer": "2.0",
		"nonce": "ABCDEFGHIJKLMNOPQRSTUVW",
		"kid": "ValidKeyIdentifier"
		"alg-id": 1,
		"pcr-details": [
		  {
		    "pcr": 0,
		    "digest": "h0KPxSKAPTEGXnvOPPA/5HUJZjHl4Hu9eg/eYMTPJcc=",
		  },
		  {
		    "pcr": 1,
		    "digest": "h0KPySKAPTEGXnvOPPA/5HUJZjHl4Hu9eg/eYMTPJcc=",
		  },
		]
	}`)
)
