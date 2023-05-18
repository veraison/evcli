// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock_deps "github.com/veraison/evcli/v2/cmd/mocks"
	"github.com/veraison/evcli/v2/common"
)

func Test_AttesterCmd_claims_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	expectedErr := `open claims.json: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_platform_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	expectedErr := `error loading Platform signing key from iak.jwk: open iak.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_realm_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	expectedErr := `error loading Realm signing key from rak.jwk: open rak.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_claims_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testInvalidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	expectedErr := "unmarshaling platform claims: unexpected end of JSON input"

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_AttesterCmd_platform_key_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	expectedErr := `error decoding Platform signing key from iak.jwk: failed to parse key: invalid key type from JSON ()`

	err = cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}

func Test_AttesterCmd_realm_key_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	expectedErr := `error decoding Realm signing key from rak.jwk: failed to parse key: invalid key type from JSON ()`

	err = cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}

func Test_AttesterCmd_bad_server_url(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, attesterVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://vera:son",
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
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
	mc.EXPECT().SetNonceSz(uint(64))
	mc.EXPECT().Run().Return([]byte("ok"), nil)

	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, mc)
	cmd.SetArgs(
		[]string{
			"--api-server=" + testSessionURI,
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_AttesterCmd_protocol_run_failed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mc := mock_deps.NewMockIVeraisonClient(ctrl)

	mc.EXPECT().SetSessionURI(testSessionURI)
	mc.EXPECT().SetEvidenceBuilder(gomock.Any())
	mc.EXPECT().SetDeleteSession(true)
	mc.EXPECT().SetNonceSz(uint(64))
	mc.EXPECT().Run().Return(nil, errors.New("failed"))

	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "iak.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "rak.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewAttesterCmd(fs, mc)
	cmd.SetArgs(
		[]string{
			"--api-server=" + testSessionURI,
			"--claims=claims.json",
			"--iak=iak.jwk",
			"--rak=rak.jwk",
		},
	)

	err = cmd.Execute()
	assert.EqualError(t, err, "error in attesterVeraisonClient Run failed")
}

func Test_attesterEvidenceBuilder_BuildCCAEvidence_ok(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "claims.json", testValidCCAClaimsNoNonce, 0644)
	require.NoError(t, err)

	pClaims, rClaims, err := loadUnValidatedCCAClaimsFromFile(fs, "claims.json")
	assert.NoError(t, err)
	pSigner, err := common.SignerFromJWK(testValidIAK)
	assert.NoError(t, err)

	rSigner, err := common.SignerFromJWK(testValidRAK)
	assert.NoError(t, err)

	mut := attesterEvidenceBuilder{
		Pclaims: pClaims, Rclaims: rClaims,
		Psigner: pSigner, Rsigner: rSigner,
	}

	supportedMediaTypes := []string{
		"a", CCATokenMediaType, "b", "c",
	}

	expectedMediaType := CCATokenMediaType
	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)
	fmt.Printf("e: %x\n", actualEvidence)
	assert.NoError(t, err)
	assert.Equal(t, expectedMediaType, actualMediaType)
}

func Test_attesterEvidenceBuilder_BuildEvidence_unsupported_media_type(t *testing.T) {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "claims.json", testValidCCAClaimsNoNonce, 0644)
	require.NoError(t, err)

	pClaims, rClaims, err := loadUnValidatedCCAClaimsFromFile(fs, "claims.json")
	assert.NoError(t, err)

	pSigner, err := common.SignerFromJWK(testValidIAK)
	assert.NoError(t, err)

	rSigner, err := common.SignerFromJWK(testValidRAK)
	assert.NoError(t, err)

	mut := attesterEvidenceBuilder{
		Pclaims: pClaims, Rclaims: rClaims,
		Psigner: pSigner, Rsigner: rSigner,
	}

	supportedMediaTypes := []string{
		"a", "b", "c",
	}

	expectedEvidence := []byte(nil)
	expectedMediaType := ""

	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)

	expectedErr := fmt.Sprintf(
		"expecting media type %s, got %s",
		CCATokenMediaType, strings.Join(supportedMediaTypes, ", "),
	)

	assert.EqualError(t, err, expectedErr)
	assert.Equal(t, expectedEvidence, actualEvidence)
	assert.Equal(t, expectedMediaType, actualMediaType)
}
