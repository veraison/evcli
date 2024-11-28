// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"github.com/veraison/ccatoken"
	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/ccatoken/realm"
)

func loadCCAClaimsFromFile(fs afero.Fs, fn string, validate bool) (*ccatoken.Evidence, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	if validate {
		return ccatoken.DecodeAndValidateEvidenceFromJSON(buf)
	}

	return ccatoken.DecodeEvidenceFromJSON(buf)
}

func loadUnValidatedCCAClaimsFromFile(fs afero.Fs, fn string) (platform.IClaims, realm.IClaims, error) {
	var c ccatoken.JSONCollection

	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, nil, err
	}

	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling CCA claims: %w", err)
	}

	// platform
	p, err := platform.DecodeClaimsFromJSON(c.PlatformToken)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshaling platform claims: %w", err)
	}

	// realm
	r, err := realm.DecodeClaimsFromJSON(c.RealmToken)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshaling realm claims: %w", err)
	}

	return p, r, nil
}

func loadTokenFromFile(fs afero.Fs, fn string) (*ccatoken.Evidence, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	return ccatoken.DecodeAndValidateEvidenceFromCBOR(buf)
}
