// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/ccatoken"
	"github.com/veraison/evcli/common"
)

var (
	createClaimsFile *string
	createRAKFile    *string
	createPAKFile    *string
	createTokenFile  *string
)

var createCmd = NewCreateCmd(common.Fs)

func NewCreateCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a CCA attestation token from the supplied claims and keys",
		Long: `Create a CCA attestation token from the JSON-encoded claims and
keys (PAK and RAK)
		
Create a CCA attestation token from claims contained in claims.json, sign
with pak.jwk and rak.jwk and save the result to my.cbor:
	
	evcli cca create --claims=claims.json --pak=pak.jwk --rak=rak.jwk --token=my.cbor
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			evidence, err := loadCCAClaimsFromFile(fs, *createClaimsFile)
			if err != nil {
				return fmt.Errorf(
					"error loading CCA claims from %s: %w",
					*createClaimsFile, err,
				)
			}

			rak, err := afero.ReadFile(fs, *createRAKFile)
			if err != nil {
				return fmt.Errorf(
					"error loading RAK signing key from %s: %w",
					*createRAKFile, err,
				)
			}

			rSigner, err := common.SignerFromJWK(rak)
			if err != nil {
				return fmt.Errorf(
					"error decoding RAK signing key from %s: %w",
					*createRAKFile, err,
				)
			}

			pak, err := afero.ReadFile(fs, *createPAKFile)
			if err != nil {
				return fmt.Errorf(
					"error loading PAK signing key from %s: %w",
					*createPAKFile, err,
				)
			}

			pSigner, err := common.SignerFromJWK(pak)
			if err != nil {
				return fmt.Errorf(
					"error decoding PAK signing key from %s: %w",
					*createPAKFile, err,
				)
			}

			b, err := evidence.Sign(pSigner, rSigner)
			if err != nil {
				return fmt.Errorf("error signing evidence: %w", err)
			}

			fn := tokenFileName()

			err = afero.WriteFile(fs, fn, b, 0644)
			if err != nil {
				return fmt.Errorf(
					"error saving CCA attestation token to file %s: %w",
					fn, err,
				)
			}

			fmt.Printf(">> %q successfully created\n", fn)

			return nil
		},
	}

	createClaimsFile = cmd.Flags().StringP(
		"claims", "c", "", "JSON file containing the CCA attestation claims to be signed",
	)

	createRAKFile = cmd.Flags().StringP(
		"rak", "r", "", "JWK file with the key used for signing the realm token",
	)

	createPAKFile = cmd.Flags().StringP(
		"pak", "p", "", "JWK file with the key used for signing the platform token",
	)

	createTokenFile = cmd.Flags().StringP(
		"token", "t", "", "name of the file where the produced CCA attestation token will be stored",
	)

	return cmd
}

func init() {
	for _, param := range []string{"claims", "rak", "pak"} {
		if err := createCmd.MarkFlagRequired(param); err != nil {
			panic(err)
		}
	}
}

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

func tokenFileName() string {
	if createTokenFile == nil || *createTokenFile == "" {
		return common.MakeFileName(".", *createClaimsFile, ".cbor")
	}

	return *createTokenFile
}
