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

func loadClaimsFromFile(fs afero.Fs, fn string, partial bool) (psatoken.IClaims, error) {
	buf, err := afero.ReadFile(fs, fn)
	if err != nil {
		return nil, err
	}

	// Check first for P2 Claims
	p2 := &psatoken.P2Claims{}

	err2 := json.Unmarshal(buf, p2)
	if err2 == nil {
		err2 = p2.Validate()
		if partial || (err2 == nil) {
			return p2, nil
		}
	}
	p1 := &psatoken.P1Claims{}

	err1 := json.Unmarshal(buf, p1)
	if err1 == nil {
		err1 = p1.Validate()
		if partial || err1 == nil {
			return p1, nil
		}
	}

	return nil, fmt.Errorf("p1 error: (%v) and p2 error: (%v)", err1, err2)
}
