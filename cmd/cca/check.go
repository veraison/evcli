// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/evcli/v2/common"
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
		Short: "do the syntactic and cryptographic signature checks over a CCA attestation token",
		Long: `Run the syntactic and cryptographic signature checks over the
supplied CCA attestation token.

Check a CCA attestation token contained in my.cbor using the public IAK in
es256.jwk and save the embedded claims to claims.json:

	evcli cca check --token=my.cbor --key=es256.jwk --claims=claims.json

Or, equivalently:

	evcli cca check -t my.cbor -k es256.jwt -c claims.json

check a CCA attestation token contained in te.cbor using the public IAK in
es256.jwk and dump the embedded claims to standard output:

	evcli cca check -t te.cbor -k es256.jwk
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := afero.ReadFile(fs, *checkKeyFile)
			if err != nil {
				return fmt.Errorf(
					"error loading verification key from %s: %w",
					*checkKeyFile, err,
				)
			}

			pak, err := common.PubKeyFromJWK(key)
			if err != nil {
				return fmt.Errorf(
					"error decoding verification key from %s: %w",
					*checkKeyFile, err,
				)
			}

			t, err := loadTokenFromFile(fs, *checkTokenFile)
			if err != nil {
				return fmt.Errorf(
					"loading CCA evidence from %s: %w",
					*checkTokenFile, err,
				)
			}

			if err = t.Verify(pak); err != nil {
				return fmt.Errorf(
					"verifying CCA evidence from %s using key from %s: %w",
					*checkTokenFile, *checkKeyFile, err,
				)
			}

			claims, err := json.MarshalIndent(t, "", "  ")
			if err != nil {
				return fmt.Errorf("serializing CCA evidence: %w", err)
			}

			if checkClaimsFile == nil || *checkClaimsFile == "" {
				fmt.Printf(">> embedded claims:\n%s\n", string(claims))
			} else {
				err = afero.WriteFile(fs, *checkClaimsFile, []byte(claims), 0644)
				if err != nil {
					return fmt.Errorf("error saving CCA attestation claims to file %s: %w", *checkClaimsFile, err)
				}
			}

			return nil
		},
	}

	checkClaimsFile = cmd.Flags().StringP(
		"claims",
		"c",
		"",
		"file where the CCA attestation claims extracted from the token are saved.  Default is to use stdout",
	)

	checkKeyFile = cmd.Flags().StringP(
		"key", "k", "", "JWK file with the public Initial Attestation Key used for verification",
	)

	checkTokenFile = cmd.Flags().StringP(
		"token", "t", "", "CBOR file containing the CCA attestation token to be verified",
	)

	return cmd
}

func init() {
	if err := checkCmd.MarkFlagRequired("token"); err != nil {
		panic(err)
	}
	if err := checkCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
}
