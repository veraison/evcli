// Copyright 2023-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/ccatoken"
	"github.com/veraison/evcli/v2/common"
)

var (
	relyingPartyTokenFile  *string
	relyingPartyAPIURL     string
	relyingPartyIsInsecure bool
	relyingPartyCerts      []string
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
already well-formed CCA attestation token, possibly produced by a
previous invocation to "evcli cca create" command.

	evcli cca verify-as relying-party \
	              --api-server=https://veraison.example/challenge-response/v1/newSession \
	              --token=cca-token.cbor

	`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := relyingPartyCheckSubmitArgs(); err != nil {
				return err
			}

			token, err := afero.ReadFile(fs, *relyingPartyTokenFile)
			if err != nil {
				return err
			}

			var e ccatoken.Evidence

			if err = e.FromCBOR(token); err != nil {
				return fmt.Errorf("ingesting %s: %v", *relyingPartyTokenFile, err)
			}

			nonce, err := e.RealmClaims.GetChallenge()
			if err != nil {
				return fmt.Errorf("cannot extract challenge from %s: %v",
					*relyingPartyTokenFile, err)
			}

			if err = veraisonClient.SetNonce(nonce); err != nil {
				return fmt.Errorf(
					"cannot configure nonce in Veraison API client: %v",
					err,
				)
			}

			if err = veraisonClient.SetSessionURI(relyingPartyAPIURL); err != nil {
				return fmt.Errorf(
					"cannot configure URL in Veraison API client: %v",
					err,
				)
			}

			eb := relyingPartyEvidenceBuilder{Token: token, Nonce: nonce}
			if err = veraisonClient.SetEvidenceBuilder(eb); err != nil {
				return fmt.Errorf(
					"cannot configure evidence builder in Veraison API client: %v",
					err,
				)
			}

			veraisonClient.SetDeleteSession(true)
			veraisonClient.SetIsInsecure(relyingPartyIsInsecure)
			veraisonClient.SetCerts(relyingPartyCerts)

			attestationResults, err := veraisonClient.Run()
			if err != nil {
				return fmt.Errorf("Veraison API client failed: %v", err)
			}

			fmt.Println(string(attestationResults))

			return nil
		},
	}

	relyingPartyTokenFile = cmd.Flags().StringP(
		"token", "t", "", "file containing a signed CCA attestation token",
	)

	cmd.Flags().StringP(
		"api-server", "s", "", "URL of the Veraison verification API",
	)

	cmd.Flags().BoolP(
		"insecure", "i", false, "Allow insecure connections (e.g. do not verify TLS certs)",
	)

	cmd.Flags().StringArrayP(
		"ca-cert", "E", nil, "path to a CA cert that will be used in addition to system certs; may be specified multiple times",
	)

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		cfgName := strings.ReplaceAll(flag.Name, "-", "_")
		if cfgName == "token" {
			// as token is likely to be different on each
			// invocation, it does not make sense for it be
			// specified via the config.
			return
		}

		err := viper.BindPFlag(cfgName, flag)
		cobra.CheckErr(err)
	})

	return cmd
}

func relyingPartyCheckSubmitArgs() error {
	relyingPartyAPIURL = viper.GetString("api_server")
	if relyingPartyAPIURL == "" {
		return errors.New("API server URL is not configured")
	}

	relyingPartyIsInsecure = viper.GetBool("insecure")
	relyingPartyCerts = viper.GetStringSlice("ca_cert")

	return nil
}

type relyingPartyEvidenceBuilder struct {
	Token []byte
	Nonce []byte
}

func (eb relyingPartyEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct == CCATokenMediaType {
			if bytes.Equal(nonce, eb.Nonce) {
				return eb.Token, CCATokenMediaType, nil
			}
			return nil, "", fmt.Errorf("expecting nonce %x, got %x", eb.Nonce, nonce)
		}
	}

	return nil, "", fmt.Errorf("expecting media type %s, got %s", CCATokenMediaType, strings.Join(accept, ", "))
}

func init() {
	if err := relyingPartyCmd.MarkFlagRequired("token"); err != nil {
		panic(err)
	}
}
