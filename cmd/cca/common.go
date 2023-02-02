// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"github.com/veraison/ccatoken"
	"github.com/veraison/psatoken"
)

func loadCCAClaimsFromFile(fs afero.Fs, fn string) (*ccatoken.Evidence, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	var e ccatoken.Evidence
	if err := e.UnmarshalJSON(buf); err != nil {
		return nil, err
	}

	return &e, nil
}

func loadUnValidatedCCAClaimsFromFile(fs afero.Fs, fn string) (psatoken.IClaims, ccatoken.IClaims, error) {
	var c ccatoken.JSONCollection

	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, nil, err
	}

	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling CCA claims: %w", err)
	}

	// platform
	p := &psatoken.CcaPlatformClaims{}

	if err := json.Unmarshal(c.PlatformToken, &p); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling platform claims: %w", err)
	}

	// realm
	r := &ccatoken.RealmClaims{}

	if err := json.Unmarshal(c.RealmToken, &r); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling realm claims: %w", err)
	}
	return p, r, nil
}
