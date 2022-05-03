// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"os"

	"github.com/spf13/cobra"
)

var verifyValidArgs = []string{"attester", "relying-party"}

const PSATokenMediaType = "application/psa-attestation-token"

var verifyAsCmd = &cobra.Command{
	Use:   "verify-as",
	Short: "use Veraison REST API to verify PSA tokens",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help() // nolint: errcheck
			os.Exit(0)
		}
	},
	ValidArgs: verifyValidArgs,
}

func init() {
	verifyAsCmd.AddCommand(relyingPartyCmd)
	verifyAsCmd.AddCommand(attesterCmd)
}
