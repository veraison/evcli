// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/afero"
	"github.com/veraison/go-cose"
)

var Fs = afero.NewOsFs()

func getAlgAndKeyFromJWK(rawJWK []byte) (cose.Algorithm, crypto.Signer, error) {
	var (
		crv    elliptic.Curve
		alg    cose.Algorithm
		rawkey crypto.Signer
	)

	key, err := jwk.ParseKey(rawJWK)
	if err != nil {
		return alg, rawkey, fmt.Errorf("failed to parse key: %w", err)
	}

	if err := key.Raw(&rawkey); err != nil {
		return alg, rawkey, fmt.Errorf("failed to create key: %w", err)
	}

	switch v := rawkey.(type) {
	case *rsa.PrivateKey:
		alg = cose.AlgorithmES256
	case *ecdsa.PrivateKey:
		crv = v.Curve
		if crv == elliptic.P256() {
			alg = cose.AlgorithmES256
			break
		}
		if crv == elliptic.P384() {
			alg = cose.AlgorithmES384
			break
		}
		return alg, rawkey, fmt.Errorf("unknown elliptic curve %v", crv)
	default:
		return alg, rawkey, fmt.Errorf("unknown private key type %v", reflect.TypeOf(key))
	}
	return alg, rawkey, nil
}

// SignerFromJWK creates a go-cose Signer object from the supplied JSON Web Key
// (JWK) description
func SignerFromJWK(rawJWK []byte) (cose.Signer, error) {
	var noSigner cose.Signer
	alg, rawkey, err := getAlgAndKeyFromJWK(rawJWK)
	if err != nil {
		return noSigner, err
	}

	return cose.NewSigner(alg, rawkey)
}

// PubKeyFromJWK extracts the PublicKey (if any) from the supplied JSON Web Key
// (JWK) description
func PubKeyFromJWK(rawJWK []byte) (crypto.PublicKey, error) {
	var noPubkey crypto.PublicKey
	_, key, err := getAlgAndKeyFromJWK(rawJWK)
	if err != nil {
		return noPubkey, err
	}

	return key.Public(), nil
}

func MakeFileName(dirName, baseName, ext string) string {
	return filepath.Join(
		dirName,
		filepath.Base(
			strings.TrimSuffix(
				baseName,
				filepath.Ext(baseName),
			),
		)+ext,
	)
}
