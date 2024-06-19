// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/evcli/v2/common"
)

var (
	printTokenFile  *string
)

var printCmd = NewPrintCmd(common.Fs)

func NewPrintCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "print",
		Short: "print the contents of a PSA attestation token to the standard output",
		Long: `Print the contents of the given PSA attestation token to the standard
output, without performing any cryptographic checks.

Print a PSA attestation token contained in my.cbor:

	evcli psa print --token=my.cbor

Or, equivalently:

	evcli psa print -t my.cbor
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := loadTokenFromFile(fs, *printTokenFile)
			if err != nil {
				return err
			}

			claims, err := json.MarshalIndent(t.Claims, "", "  ")
			if err != nil {
				return fmt.Errorf("claims extraction failed: %w", err)
			}

			fmt.Printf("%s\n", claims)

			return nil
		},
	}

	printTokenFile = cmd.Flags().StringP(
		"token", "t", "", "CBOR file containing the PSA attestation token to be verified",
	)

	return cmd
}

func init() {
	if err := printCmd.MarkFlagRequired("token"); err != nil {
		panic(err)
	}
}
