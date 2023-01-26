// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/afero"
	"github.com/veraison/go-cose"
)

var Fs = afero.NewOsFs()

func getAlgAndKeyFromJWK(rawJWK []byte) (cose.Algorithm, crypto.Signer, error) {
	var (
		crv  elliptic.Curve
		alg  cose.Algorithm
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
		if crv == elliptic.P256() {
			alg = cose.AlgorithmES256
			break
		}
		if crv == elliptic.P384() {
			alg = cose.AlgorithmES384
			break
		}
		return alg, sKey, fmt.Errorf("unknown elliptic curve %v", crv)
	default:
		return alg, sKey, fmt.Errorf("unknown private key type %v", reflect.TypeOf(key))
	}

	return alg, sKey, nil
}

// SignerFromJWK creates a go-cose Signer object from the supplied JSON Web Key
// (JWK) description
func SignerFromJWK(rawJWK []byte) (cose.Signer, error) {
	alg, key, err := getAlgAndKeyFromJWK(rawJWK)
	if err != nil {
		return nil, err
	}

	return cose.NewSigner(alg, key)
}

// PubKeyFromJWK extracts a crypto.PublicKey from the supplied JSON Web Key
func PubKeyFromJWK(rawJWK []byte) (crypto.PublicKey, error) {
	var pKey crypto.PublicKey

	key, err := jwk.ParseKey(rawJWK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	if err := key.Raw(&pKey); err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return pKey, nil
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

func MustHexDecode(s string) []byte {
	comments := regexp.MustCompile("#.*\n")
	emptiness := regexp.MustCompile("[ \t\n]")

	s = comments.ReplaceAllString(s, "")
	s = emptiness.ReplaceAllString(s, "")

	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
