// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"github.com/spf13/afero"
	"github.com/veraison/psatoken"
)

func loadTokenFromFile(fs afero.Fs, fn string) (*psatoken.Evidence, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	return psatoken.DecodeAndValidateEvidenceFromCOSE(buf)
}

func loadClaimsFromFile(fs afero.Fs, fn string, validate bool) (psatoken.IClaims, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	return claimsFromJSON(buf, validate)
}

func claimsFromJSON(j []byte, validate bool) (psatoken.IClaims, error) {
	if validate {
		return psatoken.DecodeAndValidateClaimsFromJSON(j)
	}
	return psatoken.DecodeClaimsFromJSON(j)
}
