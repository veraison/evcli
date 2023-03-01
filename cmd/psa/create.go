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
	allowInvalidClaims *bool
)

var createCmd = NewCreateCmd(common.Fs)

func NewCreateCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a PSA attestation token from the supplied claims and IAK",
		Long: `Create a PSA attestation token from the JSON-encoded claims and
Initial Attestation Key, optionally specifying the wanted profile

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
			validate := !*allowInvalidClaims

			if err := checkProfile(createTokenProfile); err != nil {
				return err
			}

			claims, err := loadClaimsFromFile(fs, *createClaimsFile, validate)
			if err != nil {
				return err
			}

			profile, err := claims.GetProfile()
			if err != nil {
				return fmt.Errorf("error loading profile from claims %w", err)
			}
			if profile != *createTokenProfile {
				return fmt.Errorf("profile mismatch: requested: %s loaded: %s", *createTokenProfile, profile)

			}

			evidence := psatoken.Evidence{}

			if validate {
				if err = evidence.SetClaims(claims); err != nil {
					return err
				}
			} else {
				evidence.Claims = claims
			}

			key, err := afero.ReadFile(fs, *createKeyFile)
			if err != nil {
				return fmt.Errorf("error loading signing key from %s: %w", *createKeyFile, err)
			}

			signer, err := common.SignerFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding signing key from %s: %w", *createKeyFile, err)
			}

			var cwt []byte
			if validate {
				cwt, err = evidence.Sign(signer)
			} else {
				cwt, err = evidence.SignUnvalidated(signer)
			}
			if err != nil {
				return fmt.Errorf("signature failed: %w", err)
			}

			fn := tokenFileName()

			err = afero.WriteFile(fs, fn, cwt, 0644)
			if err != nil {
				return fmt.Errorf("error saving PSA attestation token to file %s: %w", fn, err)
			}

			fmt.Printf(">> %q successfully created\n", fn)

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
		"token", "t", "", "name of the file where the produced PSA attestation token will be stored",
	)

	createTokenProfile = cmd.Flags().StringP(
		"profile", "p", psatoken.PsaProfile2, "name of the PSA profile to use",
	)

	allowInvalidClaims = cmd.Flags().BoolP(
		"allow-invalid", "I", false,
		"Do not validate provided claims, allowing invalid tokens to be generated. "+
			"This is intended for testing.",
	)

	return cmd
}

func checkProfile(profile *string) error {
	if profile == nil {
		return errors.New("nil profile")
	}

	switch *profile {
	case psatoken.PsaProfile1, psatoken.PsaProfile2:
		return nil
	}

	return fmt.Errorf(
		"wrong profile %s: allowed profiles are %s and %s",
		*profile, psatoken.PsaProfile2, psatoken.PsaProfile1,
	)
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
