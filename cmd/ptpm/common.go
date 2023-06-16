package ptpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/afero"
	"github.com/veraison/parsectpm"
)

type PcrDetails struct {
	Pcr    int    `json:"pcr"`
	Digest []byte `json:"digest"`
}

type ParsectpmClaim struct {
	TpmVer     *string      `json:"tpmVer"`
	Nonce      *[]byte      `json:"nonce"`
	KID        *[]byte      `json:"kid"`
	AlgID      uint         `json:"alg-id"`
	PcrDetails []PcrDetails `json:"pcr-details"`
}

func loadParsectpmClaimsFromFile(fs afero.Fs, fn string) (*ParsectpmClaim, error) {
	var pc ParsectpmClaim

	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(buf, &pc); err != nil {
		return nil, fmt.Errorf("error unmarshalling Parsec TPM claim set: %w", err)
	}

	return &pc, nil
}

func getAlgAndKeyFromJWK(rawJWK []byte) (parsectpm.Algorithm, crypto.Signer, error) {
	var (
		crv  elliptic.Curve
		alg  parsectpm.Algorithm
		sKey crypto.Signer
	)

	key, err := jwk.ParseKey(rawJWK)
	if err != nil {
		return alg, sKey, fmt.Errorf("failed to parse key: %w", err)
	}

	if err := key.Raw(&sKey); err != nil {
		return alg, sKey, fmt.Errorf("failed to create key: %w", err)
	}

	switch v := sKey.(type) {
	case *ecdsa.PrivateKey:
		crv = v.Curve
		switch crv {
		case elliptic.P256():
			alg = parsectpm.AlgorithmES256
		case elliptic.P384():
			alg = parsectpm.AlgorithmES384
		case elliptic.P521():
			alg = parsectpm.AlgorithmES512
		default:
			return alg, sKey, fmt.Errorf("unknown elliptic curve %v", crv)
		}
	default:
		return alg, sKey, fmt.Errorf("unknown private key type %v", reflect.TypeOf(key))
	}

	return alg, sKey, nil
}

func pubKeyFromJWK(rawJWK []byte) (crypto.PublicKey, error) {
	_, skey, err := getAlgAndKeyFromJWK(rawJWK)
	if err != nil {
		return nil, fmt.Errorf("unable to get key from JWK")
	}
	return skey.Public(), nil
}
