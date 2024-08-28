// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"os"

	"github.com/spf13/cobra"
)

var verifyValidArgs = []string{"attester", "relying-party"}

const CCATokenMediaType = `application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0"`

var verifyAsCmd = &cobra.Command{
	Use:   "verify-as",
	Short: "use Veraison REST API to verify CCA tokens",
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
