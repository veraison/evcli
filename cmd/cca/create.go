// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/evcli/v2/common"
)

var (
	createClaimsFile   *string
	createRAKFile      *string
	createIAKFile      *string
	createTokenFile    *string
	allowInvalidClaims *bool
)

var createCmd = NewCreateCmd(common.Fs)

func NewCreateCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a CCA attestation token from the supplied claims and keys",
		Long: `Create a CCA attestation token from the JSON-encoded claims and
keys (IAK and RAK)

Create a CCA attestation token from claims contained in claims.json, sign
with iak.jwk and rak.jwk and save the result to my.cbor:

	evcli cca create --claims=claims.json --iak=iak.jwk --rak=rak.jwk --token=my.cbor
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			validate := !*allowInvalidClaims

			evidence, err := loadCCAClaimsFromFile(fs, *createClaimsFile, validate)
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

			iak, err := afero.ReadFile(fs, *createIAKFile)
			if err != nil {
				return fmt.Errorf(
					"error loading IAK signing key from %s: %w",
					*createIAKFile, err,
				)
			}

			pSigner, err := common.SignerFromJWK(iak)
			if err != nil {
				return fmt.Errorf(
					"error decoding IAK signing key from %s: %w",
					*createIAKFile, err,
				)
			}

			var b []byte
			if validate {
				b, err = evidence.Sign(pSigner, rSigner)

			} else {
				b, err = evidence.SignUnvalidated(pSigner, rSigner)
			}

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

	createIAKFile = cmd.Flags().StringP(
		"iak", "p", "", "JWK file with the key used for signing the platform token",
	)

	createTokenFile = cmd.Flags().StringP(
		"token", "t", "", "name of the file where the produced CCA attestation token will be stored",
	)

	allowInvalidClaims = cmd.Flags().BoolP(
		"allow-invalid", "I", false,
		"Do not validate provided claims, allowing invalid tokens to be generated. "+
			"This is intended for testing.",
	)

	return cmd
}

func init() {
	for _, param := range []string{"claims", "rak", "iak"} {
		if err := createCmd.MarkFlagRequired(param); err != nil {
			panic(err)
		}
	}
}

func tokenFileName() string {
	if createTokenFile == nil || *createTokenFile == "" {
		return common.MakeFileName(".", *createClaimsFile, ".cbor")
	}

	return *createTokenFile
}
