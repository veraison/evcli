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

	mock_deps "github.com/veraison/evcli/cmd/mocks"
)

func Test_RelyingPartyCmd_token_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	cmd := NewRelyingPartyCmd(fs, relyingPartyVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--token=ccatoken.cbor",
		},
	)

	expectedErr := `open ccatoken.cbor: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_RelyingPartyCmd_token_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testInvalidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewRelyingPartyCmd(fs, relyingPartyVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://veraison.example/challenge-response/v1",
			"--token=ccatoken.cbor",
		},
	)

	expectedErr := `cbor decoding of CCA evidence failed: unexpected EOF`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_RelyingPartyCmd_bad_server_url(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testValidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewRelyingPartyCmd(fs, relyingPartyVeraisonClient)
	cmd.SetArgs(
		[]string{
			"--api-server=http://vera:son",
			"--token=ccatoken.cbor",
		},
	)

	expectedErr := `malformed session URI: parse "http://vera:son": invalid port ":son" after host`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_RelyingPartyCmd_ok(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mc := mock_deps.NewMockIVeraisonClient(ctrl)

	mc.EXPECT().SetNonce(testNonce)
	mc.EXPECT().SetSessionURI(testSessionURI)
	mc.EXPECT().SetEvidenceBuilder(gomock.Any())
	mc.EXPECT().SetDeleteSession(true)
	mc.EXPECT().Run().Return([]byte("ok"), nil)

	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testValidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewRelyingPartyCmd(fs, mc)
	cmd.SetArgs(
		[]string{
			"--api-server=" + testSessionURI,
			"--token=ccatoken.cbor",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_RelyingPartyCmd_protocol_run_failed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mc := mock_deps.NewMockIVeraisonClient(ctrl)

	mc.EXPECT().SetNonce(testNonce)
	mc.EXPECT().SetSessionURI(testSessionURI)
	mc.EXPECT().SetEvidenceBuilder(gomock.Any())
	mc.EXPECT().SetDeleteSession(true)
	mc.EXPECT().Run().Return(nil, errors.New("failed"))

	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testValidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewRelyingPartyCmd(fs, mc)
	cmd.SetArgs(
		[]string{
			"--api-server=" + testSessionURI,
			"--token=ccatoken.cbor",
		},
	)

	expectedErr := `failed`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_relyingPartyEvidenceBuilder_BuildEvidence_ok(t *testing.T) {
	mut := relyingPartyEvidenceBuilder{
		Token: testValidCCAToken,
		Nonce: testNonce,
	}

	supportedMediaTypes := []string{
		"a", CCATokenMediaType, "b", "c",
	}

	expectedEvidence := testValidCCAToken
	expectedMediaType := CCATokenMediaType

	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)

	assert.NoError(t, err)
	assert.Equal(t, expectedEvidence, actualEvidence)
	assert.Equal(t, expectedMediaType, actualMediaType)
}

func Test_relyingPartyEvidenceBuilder_BuildEvidence_nonce_not_matching(t *testing.T) {
	mut := relyingPartyEvidenceBuilder{
		Token: testValidCCAToken,
		Nonce: testNonce,
	}

	supportedMediaTypes := []string{
		"a", CCATokenMediaType, "b", "c",
	}

	nonMatchingNonce := []byte("another nonce")

	expectedEvidence := []byte(nil)
	expectedMediaType := ""

	actualEvidence, actualMediaType, err := mut.BuildEvidence(nonMatchingNonce, supportedMediaTypes)

	expectedErr := fmt.Sprintf("expecting nonce %x, got %x", testNonce, nonMatchingNonce)

	assert.EqualError(t, err, expectedErr)
	assert.Equal(t, expectedEvidence, actualEvidence)
	assert.Equal(t, expectedMediaType, actualMediaType)
}

func Test_relyingPartyEvidenceBuilder_BuildEvidence_unsupported_media_type(t *testing.T) {
	mut := relyingPartyEvidenceBuilder{
		Token: testValidCCAToken,
		Nonce: testNonce,
	}

	supportedMediaTypes := []string{
		"a", "b", "c",
	}

	expectedEvidence := []byte(nil)
	expectedMediaType := ""

	actualEvidence, actualMediaType, err := mut.BuildEvidence(testNonce, supportedMediaTypes)

	expectedErr := fmt.Sprintf("expecting media type %s, got %s",
		CCATokenMediaType, strings.Join(supportedMediaTypes, ", "),
	)

	assert.EqualError(t, err, expectedErr)
	assert.Equal(t, expectedEvidence, actualEvidence)
	assert.Equal(t, expectedMediaType, actualMediaType)
}
