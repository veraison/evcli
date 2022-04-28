package psa

import (
	"encoding/json"

	"github.com/spf13/afero"
	"github.com/veraison/psatoken"
)

func loadTokenFromFile(fs afero.Fs, fn string) (*psatoken.Evidence, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	e := &psatoken.Evidence{}
	err = e.FromCOSE(buf, psatoken.PSA_PROFILE_1, psatoken.PSA_PROFILE_2)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func loadClaimsFromFile(fs afero.Fs, fn string) (*psatoken.Claims, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	p := &psatoken.Claims{}
	err = json.Unmarshal(buf, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}
