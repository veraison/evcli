// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/ccatoken"
	"github.com/veraison/evcli/common"
	"github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

type attesterEvidenceBuilder struct {
	Pclaims psatoken.IClaims
	Rclaims ccatoken.IClaims
	Psigner cose.Signer
	Rsigner cose.Signer
}

const attesterNonceSz = 64

var (
	attesterClaimsFile *string
	platformKeyFile    *string
	realmKeyFile       *string
	attesterAPIURL     *string
)

var (
	attesterVeraisonClient common.IVeraisonClient = &verification.ChallengeResponseConfig{}
	attesterCmd                                   = NewAttesterCmd(common.Fs, attesterVeraisonClient)
)

func NewAttesterCmd(fs afero.Fs, attesterVeraisonClient common.IVeraisonClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attester",
		Short: "Emulate an Attester",
		Long: `This command implements the "attester mode" of a challenge-response
interaction, where the verifier is the protocol challenger.  Therefore, the nonce or 
challenge is provided by the Veraison API server and the CCA attestation token needs
to be created on the fly based on the attester's claims, platform signing key (PAK)
and realm signing key (RAK).
	
	evcli cca verify-as attester \
	              --api-server=https://veraison.example/challenge-response/v1/newSession \
	              --claims=claims.json \
	              --pak=pak.jwk \
			      --rak=rak.jwk
				   
	`,
		RunE: func(cmd *cobra.Command, args []string) error {

			pClaims, rClaims, err := loadUnValidatedCCAClaimsFromFile(fs, *attesterClaimsFile)
			if err != nil {
				return err
			}

			key, err := afero.ReadFile(fs, *platformKeyFile)
			if err != nil {
				return fmt.Errorf("error loading Platform signing key from %s: %w", *platformKeyFile, err)
			}

			platSigner, err := common.SignerFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding Platform signing key from %s: %w", *platformKeyFile, err)
			}

			key, err = afero.ReadFile(fs, *realmKeyFile)
			if err != nil {
				return fmt.Errorf("error loading Realm signing key from %s: %w", *realmKeyFile, err)
			}

			realmSigner, err := common.SignerFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding Realm signing key from %s: %w", *realmKeyFile, err)
			}

			eb := attesterEvidenceBuilder{Pclaims: pClaims, Rclaims: rClaims, Psigner: platSigner, Rsigner: realmSigner}

			if err = attesterVeraisonClient.SetEvidenceBuilder(eb); err != nil {
				return err
			}

			if err = attesterVeraisonClient.SetSessionURI(*attesterAPIURL); err != nil {
				return err
			}

			if err = attesterVeraisonClient.SetNonceSz(attesterNonceSz); err != nil {
				return err
			}

			attesterVeraisonClient.SetDeleteSession(true)
			attestationResults, err := attesterVeraisonClient.Run()
			if err != nil {
				return fmt.Errorf("error in attesterVeraisonClient Run %w", err)
			}

			fmt.Println(string(attestationResults))

			return nil
		},
	}

	attesterClaimsFile = cmd.Flags().StringP(
		"claims", "c", "", "JSON file containing the CCA attestation claims to be signed",
	)

	platformKeyFile = cmd.Flags().StringP(
		"pak", "p", "", "JWK file with the Platform Attestation Key used for signing",
	)

	realmKeyFile = cmd.Flags().StringP(
		"rak", "r", "", "JWK file with the Realm Attestation Key used for signing",
	)

	attesterAPIURL = cmd.Flags().StringP(
		"api-server", "s", "", "URL of the Veraison verification API",
	)

	return cmd
}

func (eb attesterEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct != CCATokenMediaType {
			continue
		}

		if err := eb.Rclaims.SetChallenge(nonce); err != nil {
			return nil, "", fmt.Errorf("setting nonce: %w", err)
		}

		evidence := ccatoken.Evidence{}
		if err := evidence.SetClaims(eb.Pclaims, eb.Rclaims); err != nil {
			return nil, "", fmt.Errorf("setting claims: %w", err)
		}

		cwt, err := evidence.Sign(eb.Psigner, eb.Rsigner)
		if err != nil {
			return nil, "", fmt.Errorf("signature failed: %w", err)
		}

		return cwt, CCATokenMediaType, nil
	}

	return nil, "", fmt.Errorf("expecting media type %s, got %s", CCATokenMediaType, strings.Join(accept, ", "))
}

func init() {
	if err := attesterCmd.MarkFlagRequired("claims"); err != nil {
		panic(err)
	}
	if err := attesterCmd.MarkFlagRequired("pak"); err != nil {
		panic(err)
	}
	if err := attesterCmd.MarkFlagRequired("rak"); err != nil {
		panic(err)
	}
	if err := attesterCmd.MarkFlagRequired("api-server"); err != nil {
		panic(err)
	}
}
