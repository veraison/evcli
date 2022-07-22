// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock_deps "github.com/veraison/evcli/cmd/mocks"
)

func Test_AttesterCmd_claims_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `open claims.json: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaims, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error loading signing key from es256.jwk: open es256.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_claims_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testInvalidPSAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)
	comErr := `(json: cannot unmarshal array into Go value of type psatoken.`
	expectedErr := `p1 error: ` + comErr + `P1Claims)` + ` and p2 error: ` + comErr + `P2Claims)`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_key_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error decoding signing key from es256.jwk: failed to parse key: failed to unmarshal JSON into key`

	err = cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}

func Test_AttesterCmd_bad_server_url(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://vera:son",
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `malformed session URI: parse "http://vera:son": invalid port ":son" after host`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_ok(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mc := mock_deps.NewMockIVeraisonClient(ctrl)

	mc.EXPECT().SetSessionURI(testSessionURI)
	mc.EXPECT().SetEvidenceBuilder(gomock.Any())
	mc.EXPECT().SetDeleteSession(true)
	mc.EXPECT().SetNonceSz(uint(48))
	mc.EXPECT().Run().Return([]byte("ok"), nil)

	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, mc)
	cmd.SetArgs(
		[]string{
			"--api-server=" + testSessionURI,
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_AttesterCmd_bad_nonceSz(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--key=es256.jwk",
			"--nonce-size=2",
		},
	)

	expectedErr := `wrong nonce length 2: allowed values are 32, 48 and 64`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_protocol_run_failed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mc := mock_deps.NewMockIVeraisonClient(ctrl)

	mc.EXPECT().SetSessionURI(testSessionURI)
	mc.EXPECT().SetEvidenceBuilder(gomock.Any())
	mc.EXPECT().SetDeleteSession(true)
	mc.EXPECT().SetNonceSz(uint(48))
	mc.EXPECT().Run().Return(nil, errors.New("failed"))

	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, mc)
	cmd.SetArgs(
		[]string{
			"--api-server=" + testSessionURI,
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	err = cmd.Execute()
	assert.EqualError(t, err, "failed")
}

func Test_attesterEvidenceBuilder_BuildP2Evidence_ok(t *testing.T) {
	mut := attesterEvidenceBuilder{
		Claims: makeClaimsFromJSON(testValidP2PSAClaims, false),
		Signer: makeSignerFromJWK(testValidKey),
	}

	supportedMediaTypes := []string{
		"a", PSATokenMediaType, "b", "c",
	}

	const (
		ecdsaSignatureLen = 64
	)

	expectedEvidenceWithoutSignature := testValidP2PSAToken[:len(testValidP2PSAToken)-ecdsaSignatureLen]
	expectedMediaType := PSATokenMediaType

	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)

	fmt.Printf("e: %x\n", actualEvidence)
	fmt.Printf("len(e): %d\n", len(actualEvidence))

	assert.NoError(t, err)
	assert.Equal(t, expectedEvidenceWithoutSignature, actualEvidence[:len(actualEvidence)-ecdsaSignatureLen])
	assert.Equal(t, expectedMediaType, actualMediaType)
}

func Test_attesterEvidenceBuilder_BuildP1Evidence_ok(t *testing.T) {
	mut := attesterEvidenceBuilder{
		Claims: makeClaimsFromJSON(testValidP1PSAClaims, true),
		Signer: makeSignerFromJWK(testValidKey),
	}

	supportedMediaTypes := []string{
		"a", PSATokenMediaType, "b", "c",
	}

	const (
		ecdsaSignatureLen = 64
	)

	expectedEvidenceWithoutSignature := testValidP1PSAToken[:len(testValidP1PSAToken)-ecdsaSignatureLen]
	expectedMediaType := PSATokenMediaType

	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)

	fmt.Printf("e: %x\n", actualEvidence)
	fmt.Printf("len(e): %d\n", len(actualEvidence))

	assert.NoError(t, err)
	assert.Equal(t, expectedEvidenceWithoutSignature, actualEvidence[:len(actualEvidence)-ecdsaSignatureLen])
	assert.Equal(t, expectedMediaType, actualMediaType)
}

func Test_attesterEvidenceBuilder_BuildEvidence_unsupported_media_type(t *testing.T) {
	mut := attesterEvidenceBuilder{
		Claims: makeClaimsFromJSON(testValidP2PSAClaims, false),
		Signer: makeSignerFromJWK(testValidKey),
	}

	supportedMediaTypes := []string{
		"a", "b", "c",
	}

	expectedEvidence := []byte(nil)
	expectedMediaType := ""

	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)

	expectedErr := fmt.Sprintf("expecting media type %s, got %s", PSATokenMediaType, strings.Join(supportedMediaTypes, ", "))

	assert.EqualError(t, err, expectedErr)
	assert.Equal(t, expectedEvidence, actualEvidence)
	assert.Equal(t, expectedMediaType, actualMediaType)
}
