// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"errors"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/evcli/common"
	"github.com/veraison/psatoken"
)

var (
	createClaimsFile   *string
	createKeyFile      *string
	createTokenFile    *string
	createTokenProfile *string
)

var createCmd = NewCreateCmd(common.Fs)

func NewCreateCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a PSA attestation token from the supplied claims and IAK",
		Long: `create a PSA attestation token from the JSON-encoded claims and Initial Attestation Key

	Create a PSA attestation token from claims contained in claims.json, sign
	with es256.jwk and save the result to my.cbor:
	
		evcli psa create --claims=claims.json --key=es256.jwk --token=my.cbor
	
	Or, equivalently:

		evcli psa create -c claims.json -k es256.jwk -t my.cbor

	Create a PSA attestation token from claims contained in te-profile1.json
	(using PSA_IOT_PROFILE_1), sign with es256.jwk and save the result to
	te-profile1.cbor:

		evcli psa create -c te-profile1.json -k es256.jwk -p PSA_IOT_PROFILE_1

	Note that the default profile is http://arm.com/psa/2.0.0.
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkProfile(createTokenProfile); err != nil {
				return err
			}

			claims, err := loadClaimsFromFile(fs, *createClaimsFile)
			if err != nil {
				return err
			}

			evidence := psatoken.Evidence{}

			if err = evidence.SetClaims(claims, *createTokenProfile); err != nil {
				return err
			}

			key, err := afero.ReadFile(fs, *createKeyFile)
			if err != nil {
				return fmt.Errorf("error loading signing key from %s: %w", *createKeyFile, err)
			}

			signer, err := common.SignerFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding signing key from %s: %w", *createKeyFile, err)
			}

			cwt, err := evidence.Sign(signer)
			if err != nil {
				return fmt.Errorf("signature failed: %w", err)
			}

			fn := tokenFileName()

			err = afero.WriteFile(fs, fn, cwt, 0644)
			if err != nil {
				return fmt.Errorf("error saving PSA attesation token to file %s: %w", fn, err)
			}

			return nil
		},
	}

	createClaimsFile = cmd.Flags().StringP(
		"claims", "c", "", "JSON file containing the PSA attestation claims to be signed",
	)

	createKeyFile = cmd.Flags().StringP(
		"key", "k", "", "JWK file with the Initial Attestation Key used for signing",
	)

	createTokenFile = cmd.Flags().StringP(
		"token", "t", "", "name of the file where the produced PSA attesation token will be stored",
	)

	createTokenProfile = cmd.Flags().StringP(
		"profile", "p", psatoken.PSA_PROFILE_2, "name of the PSA profile to use",
	)

	return cmd
}

func checkProfile(profile *string) error {
	if profile == nil {
		return errors.New("nil profile")
	}

	switch *profile {
	case psatoken.PSA_PROFILE_1, psatoken.PSA_PROFILE_2:
		return nil
	}

	return fmt.Errorf("wrong profile %s: allowed profiles are %s and %s", *profile, psatoken.PSA_PROFILE_2, psatoken.PSA_PROFILE_1)
}

func tokenFileName() string {
	if createTokenFile == nil || *createTokenFile == "" {
		return common.MakeFileName(".", *createClaimsFile, ".cbor")
	}

	return *createTokenFile
}

func init() {
	if err := createCmd.MarkFlagRequired("claims"); err != nil {
		panic(err)
	}
	if err := createCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
}
