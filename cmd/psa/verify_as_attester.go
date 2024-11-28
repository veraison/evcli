// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/evcli/v2/common"
	"github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

var (
	attesterClaimsFile *string
	attesterKeyFile    *string
	attesterAPIURL     string
	attesterNonceSz    uint
	attesterIsInsecure bool
	attesterCerts      []string
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
interaction, where the verifier is the protocol challenger.  Therefore, the
nonce is provided by the Veraison API server and the PSA attestation token needs
to be created on the fly based on the attester's claims and signing IAK.
	
	evcli psa verify-as attester \
	              --api-server=https://veraison.example/challenge-response/v1/newSession \
	              --claims=claims.json \
	              --key=es256.jwk \
	              --nonce-size=32
	
	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := attesterCheckSubmitArgs(); err != nil {
				return err
			}

			validateClaims := false
			claims, err := loadClaimsFromFile(fs, *attesterClaimsFile, validateClaims)
			if err != nil {
				return err
			}

			key, err := afero.ReadFile(fs, *attesterKeyFile)
			if err != nil {
				return fmt.Errorf("error loading signing key from %s: %w",
					*attesterKeyFile, err)
			}

			signer, err := common.SignerFromJWK(key)
			if err != nil {
				return fmt.Errorf("error decoding signing key from %s: %w",
					*attesterKeyFile, err)
			}

			eb := attesterEvidenceBuilder{Claims: claims, Signer: signer}
			if err = attesterVeraisonClient.SetEvidenceBuilder(eb); err != nil {
				return err
			}

			if err = attesterVeraisonClient.SetSessionURI(attesterAPIURL); err != nil {
				return err
			}

			if err = attesterVeraisonClient.SetNonceSz(attesterNonceSz); err != nil {
				return err
			}

			attesterVeraisonClient.SetDeleteSession(true)
			attesterVeraisonClient.SetIsInsecure(attesterIsInsecure)
			attesterVeraisonClient.SetCerts(attesterCerts)

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

	cmd.Flags().StringP(
		"api-server", "s", "", "URL of the Veraison verification API",
	)

	cmd.Flags().UintP(
		"nonce-size", "n", 48, "nonce size (32, 48 or 64)",
	)

	cmd.Flags().BoolP(
		"insecure", "i", false, "Allow insecure connections (e.g. do not verify TLS certs)",
	)

	cmd.Flags().StringArrayP(
		"ca-cert", "E", nil, "path to a CA cert that will be used in addition to system certs; may be specified multiple times",
	)

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		cfgName := strings.ReplaceAll(flag.Name, "-", "_")
		if cfgName == "claims" || cfgName == "key" {
			// as claims and the corresponding key file are likely
			// to be different on each invocation, it does not make
			// sense for them be specified via the config.
			return
		}

		err := viper.BindPFlag(cfgName, flag)
		cobra.CheckErr(err)
	})

	return cmd
}

func attesterCheckSubmitArgs() error {
	attesterAPIURL = viper.GetString("api_server")
	if attesterAPIURL == "" {
		return errors.New("API server URL is not configured")
	}

	attesterNonceSz = viper.GetUint("nonce_size")
	if err := checkNonceSz(attesterNonceSz); err != nil {
		return err
	}

	attesterIsInsecure = viper.GetBool("insecure")
	attesterCerts = viper.GetStringSlice("ca_cert")

	return nil
}

func checkNonceSz(sz uint) error {
	if sz == 0 {
		return errors.New("nonce size not specified")
	}

	switch sz {
	case 32, 48, 64:
		return nil
	}

	return fmt.Errorf("wrong nonce length %d: allowed values are 32, 48 and 64", sz)
}

type attesterEvidenceBuilder struct {
	Claims psatoken.IClaims
	Signer cose.Signer
}

func (eb attesterEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct != PSATokenMediaType {
			continue
		}

		if err := eb.Claims.SetNonce(nonce); err != nil {
			return nil, "", fmt.Errorf("setting nonce: %w", err)
		}

		_, err := eb.Claims.GetProfile()
		if err != nil {
			return nil, "", fmt.Errorf("getting profile: %w", err)
		}

		evidence := psatoken.Evidence{}

		if err = evidence.SetClaims(eb.Claims); err != nil {
			return nil, "", fmt.Errorf("setting claims: %w", err)
		}

		cwt, err := evidence.ValidateAndSign(eb.Signer)
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
}
