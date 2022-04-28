// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/evcli/common"
)

var (
	checkClaimsFile *string
	checkKeyFile    *string
	checkTokenFile  *string
)

var checkCmd = NewCheckCmd(common.Fs)

func NewCheckCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "do the syntactic and cryptographic signature checks over a PSA attestation token",
		Long: `Run the syntactic and cryptographic signature checks over the supplied PSA attestation token.

	Check a PSA attestation token contained in my.cbor using es256.jwk and (if
	possible) save the embedded claims to claims.json:
	
		evcli psa check --token=my.cbor --key=es256.jwk --claims=claims.json
	
	Or, equivalently:

		evcli psa check -t my.cbor -k es256.jwt -c claims.json

	check a PSA attestation token contained in te.json using the public IAK in
	es256.jwk and dump the embedded claims (if possible) to standard output:
	
		evcli psa check -t te.cbor -k es256.jwk
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := afero.ReadFile(fs, *checkKeyFile)
			if err != nil {
				return fmt.Errorf("error loading verification key from %s: %w", *checkKeyFile, err)
			}

			pk, err := common.PubKeyFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding verification key from %s: %w", *checkKeyFile, err)
			}

			t, err := loadTokenFromFile(fs, *checkTokenFile)
			if err != nil {
				return err
			}

			err = t.Verify(*pk)
			if err != nil {
				return fmt.Errorf("signature verification failed: %w", err)
			}
			fmt.Printf(">> %q verified\n", *checkTokenFile)

			claims, err := t.Claims.ToJSON()
			if err != nil {
				return fmt.Errorf("claims extraction failed: %w", err)
			}

			if checkClaimsFile == nil || *checkClaimsFile == "" {
				fmt.Printf(">> embedded claims:\n%s\n", claims)
			} else {
				err = afero.WriteFile(fs, *checkClaimsFile, []byte(claims), 0644)
				if err != nil {
					return fmt.Errorf("error saving PSA attesation claims to file %s: %w", *checkClaimsFile, err)
				}
			}

			return nil
		},
	}

	checkClaimsFile = cmd.Flags().StringP(
		"claims", "c", "", "file where the PSA attestation claims extracted from the token are saved.  Default is to use stdout",
	)

	checkKeyFile = cmd.Flags().StringP(
		"key", "k", "", "JWK file with the public Initial Attestation Key used for verification",
	)

	checkTokenFile = cmd.Flags().StringP(
		"token", "t", "", "CBOR file containing the PSA attesation token to be verified",
	)

	return cmd
}

func init() {
	if err := checkCmd.MarkFlagRequired("claims"); err != nil {
		panic(err)
	}
	if err := checkCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
}
