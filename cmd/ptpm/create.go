// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ptpm

import (
	"crypto"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/evcli/v2/common"
	"github.com/veraison/parsectpm"
)

var (
	createClaimsFile *string
	createCKFile     *string
	createSKFile     *string
	createTokenFile  *string
)

var createCmd = NewCreateCmd(common.Fs)

func NewCreateCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a Parsectpm attestation token from the supplied claims and keys",
		Long: `Create a Parsectpm attestation token from the JSON-encoded claims and
supplied Credential and Signing keys (CK and SK)

Create a Parsectpm attestation token from claims contained in claims.json and credential key
supplied using ck.jwk and signature key sk.jwk and save the result to parsectpm.cbor:

	evcli parsectpm create --claims=claims.json --ck=ck.jwk --sk=sk.jwk --token=my.cbor
	`,
		RunE: func(cmd *cobra.Command, args []string) error {

			pc, err := loadParsectpmClaimsFromFile(fs, *createClaimsFile)
			if err != nil {
				return fmt.Errorf(
					"error loading Parsectpm claims from %s: %w",
					*createClaimsFile, err,
				)
			}

			ck, err := afero.ReadFile(fs, *createCKFile)
			if err != nil {
				return fmt.Errorf(
					"error loading Credential key from %s: %w",
					*createCKFile, err,
				)
			}

			pubCk, err := pubKeyFromJWK(ck)
			if err != nil {
				return fmt.Errorf(
					"error decoding Public key from credential key from %s: %w",
					*createCKFile, err,
				)
			}

			sk, err := afero.ReadFile(fs, *createSKFile)
			if err != nil {
				return fmt.Errorf(
					"error loading signing key from %s: %w",
					*createSKFile, err,
				)
			}

			alg, signer, err := getAlgAndKeyFromJWK(sk)
			if err != nil {
				return fmt.Errorf(
					"error decoding Signing key from %s: %w",
					*createSKFile, err,
				)
			}

			e, err := createEvidence(pc, alg, pubCk, signer)
			if err != nil {
				return fmt.Errorf(
					"evidence creation error: %w", err,
				)
			}

			b, err := e.ToCBOR()
			if err != nil {
				return fmt.Errorf(
					"evidence ToCBOR failed: %w", err,
				)
			}
			fn := tokenFileName()

			err = afero.WriteFile(fs, fn, b, 0644)
			if err != nil {
				return fmt.Errorf(
					"error saving CCA attestation token to file %s: %w",
					fn, err,
				)
			}

			fmt.Printf(">> %q successfully created\n", fn)

			return nil
		},
	}

	createClaimsFile = cmd.Flags().StringP(
		"claims", "c", "", "JSON file containing the CCA attestation claims to be signed",
	)

	createCKFile = cmd.Flags().StringP(
		"rak", "r", "", "JWK file with the key used for signing the realm token",
	)

	createSKFile = cmd.Flags().StringP(
		"iak", "p", "", "JWK file with the key used for signing the platform token",
	)

	createTokenFile = cmd.Flags().StringP(
		"token", "t", "", "name of the file where the produced parsectpm attestation token will be stored",
	)

	return cmd
}

func createEvidence(pc *ParsectpmClaim, alg parsectpm.Algorithm, ck crypto.PublicKey, sk crypto.Signer) (*parsectpm.Evidence, error) {

	var e parsectpm.Evidence
	var k parsectpm.KAT
	var p parsectpm.PAT

	if err := k.SetTpmVer(*pc.TpmVer); err != nil {
		return nil, fmt.Errorf("failed to set TpmVer in KAT: %v", err)
	}
	if err := k.SetKeyID(*pc.KID); err != nil {
		return nil, fmt.Errorf("failed to set KID in KAT: %v", err)
	}

	// First Encode PubArea
	if err := k.EncodePubArea(alg, ck); err != nil {
		return nil, fmt.Errorf("failed to encode pubArea: %v", err)
	}

	// Then Encode CertInfo
	if err := k.EncodeCertInfo(*pc.Nonce); err != nil {
		return nil, fmt.Errorf("failed to encode CertInfo: %v", err)
	}

	// Then Generate SIG bytes using the Signature API on CertInfo
	sig, err := e.Sign(*k.CertInfo, alg, sk)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CertInfo: %v", err)
	}

	if err := k.SetSig(sig); err != nil {
		return nil, fmt.Errorf("failed to set KAT signature: %v", err)
	}

	if err := p.SetTpmVer(*pc.TpmVer); err != nil {
		return nil, fmt.Errorf("failed to set TpmVer in PAT: %v", err)
	}
	if err := p.SetKeyID(*pc.KID); err != nil {
		return nil, fmt.Errorf("failed to set KID in PAT: %v", err)
	}
	att, err := attInfoFromClaims(pc)
	if err != nil {
		return nil, fmt.Errorf("failed to get valid AttestationInfo: %v", err)
	}
	if err := p.EncodeAttestationInfo(att); err != nil {
		return nil, fmt.Errorf("failed to encode AttestationInfo: %v", err)
	}
	// Then Generate SIG bytes using the Signature API on AttestInfo
	sig, err = e.Sign(*p.AttestInfo, alg, sk)
	if err != nil {
		return nil, fmt.Errorf("failed to sign AttestInfo: %v", err)
	}

	if err := p.SetSig(sig); err != nil {
		return nil, fmt.Errorf("failed to set PAT signature: %v", err)
	}

	if err := e.SetTokens(&k, &p); err != nil {
		return nil, fmt.Errorf("unable to set valid KAT and PAT in Evidence: %v", err)
	}
	return &e, nil
}

func attInfoFromClaims(pc *ParsectpmClaim) (*parsectpm.AttestationInfo, error) {
	var att parsectpm.AttestationInfo

	return &att, nil

}
func init() {
	for _, param := range []string{"claims", "rak", "iak"} {
		if err := createCmd.MarkFlagRequired(param); err != nil {
			panic(err)
		}
	}
}

func tokenFileName() string {
	if createTokenFile == nil || *createTokenFile == "" {
		return common.MakeFileName(".", *createClaimsFile, ".cbor")
	}

	return *createTokenFile
}
