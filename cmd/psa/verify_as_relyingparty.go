// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/evcli/v2/common"
	"github.com/veraison/psatoken"
)

var (
	relyingPartyTokenFile *string
	relyingPartyAPIURL    *string
)

var (
	relyingPartyVeraisonClient common.IVeraisonClient = &verification.ChallengeResponseConfig{}
	relyingPartyCmd                                   = NewRelyingPartyCmd(common.Fs, relyingPartyVeraisonClient)
)

func NewRelyingPartyCmd(fs afero.Fs, veraisonClient common.IVeraisonClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relying-party",
		Short: "Emulate a Relying Party",
		Long: `This command implements the "relying party mode" of a
challenge-response interaction, where the relying party was the original
challenger, and therefore the nonce is provided by the caller implicitly in an
already well-formed and signed PSA attestation token, possibly produced by a
previous invocation to "evcli psa create".

	evcli psa verify-as relying-party \
	              --api-server=https://veraison.example/challenge-response/v1/newSession \
	              --token=psa-token.cbor

	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := afero.ReadFile(fs, *relyingPartyTokenFile)
			if err != nil {
				return err
			}

			var e psatoken.Evidence

			if err = e.FromCOSE(token); err != nil {
				return err
			}

			nonce, err := e.Claims.GetNonce()
			if err != nil {
				return err
			}

			if err = veraisonClient.SetNonce(nonce); err != nil {
				return err
			}

			if err = veraisonClient.SetSessionURI(*relyingPartyAPIURL); err != nil {
				return err
			}

			eb := relyingPartyEvidenceBuilder{Token: token, Nonce: nonce}
			if err = veraisonClient.SetEvidenceBuilder(eb); err != nil {
				return err
			}

			veraisonClient.SetDeleteSession(true)

			attestationResults, err := veraisonClient.Run()
			if err != nil {
				return err
			}

			fmt.Println(string(attestationResults))

			return nil
		},
	}

	relyingPartyTokenFile = cmd.Flags().StringP(
		"token", "t", "", "file containing a signed PSA attestation token",
	)

	relyingPartyAPIURL = cmd.Flags().StringP(
		"api-server", "s", "", "URL of the Veraison verification API",
	)

	return cmd
}

type relyingPartyEvidenceBuilder struct {
	Token []byte
	Nonce []byte
}

func (eb relyingPartyEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct == PSATokenMediaType {
			if bytes.Equal(nonce, eb.Nonce) {
				return eb.Token, PSATokenMediaType, nil
			}
			return nil, "", fmt.Errorf("expecting nonce %x, got %x", eb.Nonce, nonce)
		}
	}

	return nil, "", fmt.Errorf("expecting media type %s, got %s", PSATokenMediaType, strings.Join(accept, ", "))
}

func init() {
	if err := relyingPartyCmd.MarkFlagRequired("token"); err != nil {
		panic(err)
	}
	if err := relyingPartyCmd.MarkFlagRequired("api-server"); err != nil {
		panic(err)
	}
}
