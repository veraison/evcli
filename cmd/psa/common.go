package psa

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"github.com/veraison/psatoken"
)

func loadTokenFromFile(fs afero.Fs, fn string) (*psatoken.Evidence, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	e := &psatoken.Evidence{}
	err = e.FromCOSE(buf)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func loadClaimsFromFile(fs afero.Fs, fn string, validate bool) (psatoken.IClaims, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	return claimsFromJSON(buf, validate)
}

func claimsFromJSON(j []byte, validate bool) (psatoken.IClaims, error) {
	var (
		err1, err2 error
		p2         psatoken.P2Claims
		p1         psatoken.P1Claims
	)

	err2 = json.Unmarshal(j, &p2)
	if err2 == nil {
		if validate {
			err2 = p2.Validate()
			if err2 == nil {
				return &p2, nil
			}
		} else {
			return &p2, nil
		}
	}

	err1 = json.Unmarshal(j, &p1)
	if err1 == nil {
		if validate {
			err1 = p1.Validate()
			if err1 == nil {
				return &p1, nil
			}
		} else {
			return &p1, nil
		}
	}

	return nil, fmt.Errorf("p1 error: (%v) and p2 error: (%v)", err1, err2)
}
