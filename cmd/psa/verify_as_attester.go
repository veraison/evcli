// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/evcli/common"
	"github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

var (
	attesterClaimsFile *string
	attesterKeyFile    *string
	attesterAPIURL     *string
	attesterNonceSz    *uint
)

var (
	attesterVeraisonClient common.IVeraisonClient = &verification.ChallengeResponseConfig{}
	attesterCmd                                   = NewAttesterCmd(common.Fs, attesterVeraisonClient)
)

func NewAttesterCmd(fs afero.Fs, attesterVeraisonClient common.IVeraisonClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attester",
		Short: "Emulate an Attester",
		Long: `
	This command implements the "attester mode" of interaction, where the
	verifier is the protocol challenger.  Here, the nonce is provided by the API
	server and the PSA attestation token needs to be created on the fly based on
	the attester's claims and signing IAK.
	
		evcli psa verify-as attester \
		              --api-server=https://veraison.example/challenge-response/v1 \
		              --claims=claims.json \
		              --key=es256.jwk \
		              --nonce-size=32
	
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkNonceSz(attesterNonceSz); err != nil {
				return err
			}

			claims, err := loadClaimsFromFile(fs, *attesterClaimsFile)
			if err != nil {
				return err
			}

			key, err := afero.ReadFile(fs, *attesterKeyFile)
			if err != nil {
				return fmt.Errorf("error loading signing key from %s: %w", *attesterKeyFile, err)
			}

			signer, err := common.SignerFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding signing key from %s: %w", *attesterKeyFile, err)
			}

			eb := attesterEvidenceBuilder{Claims: claims, Signer: signer}
			if err = attesterVeraisonClient.SetEvidenceBuilder(eb); err != nil {
				return err
			}

			if err = attesterVeraisonClient.SetSessionURI(*attesterAPIURL); err != nil {
				return err
			}

			if err = attesterVeraisonClient.SetNonceSz(*attesterNonceSz); err != nil {
				return err
			}

			attesterVeraisonClient.SetDeleteSession(true)

			attestationResults, err := attesterVeraisonClient.Run()
			if err != nil {
				return err
			}

			fmt.Println(string(attestationResults))

			return nil
		},
	}

	attesterClaimsFile = cmd.Flags().StringP(
		"claims", "c", "", "JSON file containing the PSA attestation claims to be signed",
	)

	attesterKeyFile = cmd.Flags().StringP(
		"key", "k", "", "JWK file with the Initial Attestation Key used for signing",
	)

	attesterAPIURL = cmd.Flags().StringP(
		"api-server", "s", "", "URL of the Veraison verification API",
	)

	attesterNonceSz = cmd.Flags().UintP(
		"nonce-size", "n", 48, "nonce size (32, 48 or 64)",
	)

	return cmd
}

func checkNonceSz(sz *uint) error {
	if sz == nil {
		return errors.New("nil nonce size")
	}

	switch *sz {
	case 32, 48, 64:
		return nil
	}

	return fmt.Errorf("wrong nonce length %d: allowed values are 32, 48 and 64", *sz)
}

type attesterEvidenceBuilder struct {
	Claims *psatoken.Claims
	Signer *cose.Signer
}

func (eb attesterEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct != PSATokenMediaType {
			continue
		}

		if err := eb.Claims.SetNonce(nonce); err != nil {
			return nil, "", fmt.Errorf("setting nonce: %w", err)
		}

		profile, err := eb.Claims.GetProfile()
		if err != nil {
			return nil, "", fmt.Errorf("getting profile: %w", err)
		}

		evidence := psatoken.Evidence{}

		if err = evidence.SetClaims(eb.Claims, profile); err != nil {
			return nil, "", fmt.Errorf("setting claims: %w", err)
		}

		cwt, err := evidence.Sign(eb.Signer)
		if err != nil {
			return nil, "", fmt.Errorf("signature failed: %w", err)
		}

		return cwt, PSATokenMediaType, nil
	}

	return nil, "", fmt.Errorf("expecting media type %s, got %s", PSATokenMediaType, strings.Join(accept, ", "))
}

func init() {
	if err := attesterCmd.MarkFlagRequired("claims"); err != nil {
		panic(err)
	}
	if err := attesterCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := attesterCmd.MarkFlagRequired("api-server"); err != nil {
		panic(err)
	}
}
