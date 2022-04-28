// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"encoding/hex"
	"encoding/json"

	"github.com/veraison/evcli/common"
	"github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	testValidPSAToken   = mustHexDecode("d28443a10126a0590193aa1901097818687474703a2f2f61726d2e636f6d2f7073612f322e302e303a000124f8013a000124f91930003a000124fa582050515253545556575051525354555657505152535455565750515253545556573a000124fb5820deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef3a000124fc6d313233343536373839303132333a000124fd82a30162424c0258200001020400010204000102040001020400010204000102040001020400010204055820519200ff519200ff519200ff519200ff519200ff519200ff519200ff519200ffa3016450526f540258200506070805060708050607080506070805060708050607080506070805060708055820519200ff519200ff519200ff519200ff519200ff519200ff519200ff519200ff0a58200001020300010203000102030001020300010203000102030001020300010203190100582101a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a33a00012501781868747470733a2f2f7073612d76657269666965722e6f726758403fa7e42d972cc800e40aa9cd01e8b4306e09a18624a06c711a1c19f48745c5cc78e17d8f503f1139a2eceafba7befea2db5d77d550adf0b7247ec7269f7598b1")
	testInvalidPSAToken = []byte{}
	testNonce           = []byte{
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	}
	testSessionURI     = "http://veraison.example/challenge-response/v1"
	testValidPSAClaims = []byte(`{
		"profile": "http://arm.com/psa/2.0.0",
		"partition-id": 1,
		"security-life-cycle": 12288,
		"implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
		"boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
		"hardware-version": "1234567890123",
		"software-components": [
			{
				"measurement-type": "BL",
				"measurement-value": "AAECBAABAgQAAQIEAAECBAABAgQAAQIEAAECBAABAgQ=",
				"signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
			},
			{
				"measurement-type": "PRoT",
				"measurement-value": "BQYHCAUGBwgFBgcIBQYHCAUGBwgFBgcIBQYHCAUGBwg=",
				"signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
			}
		],
		"instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
		"verification-service-indicator": "https://psa-verifier.org"
	}`)
	testValidPSAClaimsWithNonce = []byte(`{
		"profile": "http://arm.com/psa/2.0.0",
		"partition-id": 1,
		"security-life-cycle": 12288,
		"implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
		"boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
		"hardware-version": "1234567890123",
		"software-components": [
			{
				"measurement-type": "BL",
				"measurement-value": "AAECBAABAgQAAQIEAAECBAABAgQAAQIEAAECBAABAgQ=",
				"signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
			},
			{
				"measurement-type": "PRoT",
				"measurement-value": "BQYHCAUGBwgFBgcIBQYHCAUGBwgFBgcIBQYHCAUGBwg=",
				"signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
			}
		],
		"instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
		"verification-service-indicator": "https://psa-verifier.org",
		"nonce": "QUp8F0FBs9DpodKK8xUg8NQimf6sQAfe2J1ormzZLxk="
	}`)
	testInvalidPSAClaims = []byte(`[]`)
	testValidKey         = []byte(`{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`)
	testInvalidKey = []byte(`[]`)
)

func makeClaimsFromJSON(j []byte) *psatoken.Claims {
	p := &psatoken.Claims{}

	err := json.Unmarshal(j, p)
	if err != nil {
		panic(err)
	}

	return p
}

func makeSignerFromJWK(j []byte) *cose.Signer {
	s, err := common.SignerFromJWK(j)
	if err != nil {
		panic(err)
	}

	return s
}
