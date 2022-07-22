// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"encoding/hex"

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
	testValidP2PSAToken = mustHexDecode("d28443a10126a0590174a91901097818687474703a2f2f61726d2e636f6d2f7073612f322e302e3019095a0119095b19300019095c5820505152535455565750515253545556575051525354555657505152535455565719095d5820deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef19095f82a30162424c0258200001020400010204000102040001020400010204000102040001020400010204055820519200ff519200ff519200ff519200ff519200ff519200ff519200ff519200ffa3016450526f540258200506070805060708050607080506070805060708050607080506070805060708055820519200ff519200ff519200ff519200ff519200ff519200ff519200ff519200ff0a58200001020300010203000102030001020300010203000102030001020300010203190100582101a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3190960781868747470733a2f2f7073612d76657269666965722e6f72675840dbb4871fbb6ebcd573502e98a30743291628fa5286f056f6f848c2107f59abe0f9ee034cbd68d8e7ed1d7a073fbd1039d9637dbde057197f5b096669ea9a2b7b")
	testInvalidPSAToken = []byte{}
	testNonce           = []byte{
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	}
	testSessionURI       = "http://veraison.example/challenge-response/v1"
	testValidP2PSAClaims = []byte(`{
		"eat-profile": "http://arm.com/psa/2.0.0",
		"psa-client-id": 1,
		"psa-security-lifecycle": 12288,
		"psa-implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
		"psa-boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
		"hardware-version": "1234567890123",
		"psa-software-components": [
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
		"psa-instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
		"psa-verification-service-indicator": "https://psa-verifier.org"
	}`)
	testValidP2PSAClaimsWithNonce = []byte(`{
		"eat-profile": "http://arm.com/psa/2.0.0",
		"psa-client-id": 1,
		"psa-security-lifecycle": 12288,
		"psa-implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
		"psa-boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
		"psa-hardware-version": "1234567890123",
		"psa-software-components": [
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
		"psa-instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
		"psa-verification-service-indicator": "https://psa-verifier.org",
		"psa-nonce": "QUp8F0FBs9DpodKK8xUg8NQimf6sQAfe2J1ormzZLxk="
	}`)
	testInvalidPSAClaims = []byte(`[]`)
	testValidKey         = []byte(`{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`)
	testInvalidKey       = []byte(`[]`)
	testValidP1PSAToken  = mustHexDecode("d28443a10126a0590180a93a000124f7715053415f494f545f50524f46494c455f313a000124f8013a000124f91930003a000124fa582050515253545556575051525354555657505152535455565750515253545556573a000124fb5820deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef3a000124fd82a30162424c0258200001020400010204000102040001020400010204000102040001020400010204055820519200ff519200ff519200ff519200ff519200ff519200ff519200ff519200ffa3016450526f540258200506070805060708050607080506070805060708050607080506070805060708055820519200ff519200ff519200ff519200ff519200ff519200ff519200ff519200ff3a000124ff582000010203000102030001020300010203000102030001020300010203000102033a00012500582101a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a3a0a1a2a33a00012501781868747470733a2f2f7073612d76657269666965722e6f726758405f0379f600d53acdc77259a8c0612204e84ff7a5b3f99a571a31d3f947d70ce135ec11be6ffeebc7bf5de43157f3c51dff08711b563996941d091e9532954848")
	testValidP1PSAClaims = []byte(`{
			"psa-profile": "PSA_IOT_PROFILE_1",
			"psa-client-id": 1,
			"psa-security-lifecycle": 12288,
			"psa-implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
			"psa-boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
			"psa-hwver": "1234567890123",
			"psa-software-components": [
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
			"psa-instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
			"psa-verification-service-indicator": "https://psa-verifier.org",
			"psa-nonce": "QUp8F0FBs9DpodKK8xUg8NQimf6sQAfe2J1ormzZLxk="
		  }`)
)

func makeClaimsFromJSON(j []byte, validate bool) psatoken.IClaims {
	claims, err := claimsFromJSON(j, validate)
	if err != nil {
		panic(err)
	}
	return claims

}

func makeSignerFromJWK(j []byte) cose.Signer {
	s, err := common.SignerFromJWK(j)
	if err != nil {
		panic(err)
	}

	return s
}
