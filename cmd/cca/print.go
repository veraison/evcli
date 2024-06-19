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
	printTokenFile  *string
)

var printCmd = NewPrintCmd(common.Fs)

func NewPrintCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "print",
		Short: "Write the claims in the supplied CCA attestation token to standard output",
		Long: `Write the claims in the supplied CCA attestation token to standard output.

To pretty-print a CCA attestation token contained in my.cbor:

	evcli cca print --token=my.cbor

Or, equivalently:

	evcli cca print -t my.cbor
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := loadTokenFromFile(fs, *printTokenFile)
			if err != nil {
				return fmt.Errorf(
					"loading CCA evidence from %s: %w",
					*printTokenFile, err,
				)
			}

			claims, err := json.MarshalIndent(t, "", "    ")
			if err != nil {
				return fmt.Errorf("serializing CCA evidence: %w", err)
			}

			fmt.Printf("%s\n", string(claims))

			return nil
		},
	}

	printTokenFile = cmd.Flags().StringP(
		"token", "t", "", "CBOR file containing the CCA attestation token to be printed",
	)

	return cmd
}

func init() {
	if err := printCmd.MarkFlagRequired("token"); err != nil {
		panic(err)
	}
}
