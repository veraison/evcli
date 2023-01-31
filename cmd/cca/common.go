// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
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

func loadCCAClaimsFromJSON(buf []byte) (psatoken.IClaims, ccatoken.IClaims, error) {
	var e ccatoken.Evidence
	if err := e.UnmarshalJSON(buf); err != nil {
		return nil, nil, err
	}
	return e.PlatformClaims, e.RealmClaims, nil
}
