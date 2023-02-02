// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CheckCmd_claims_to_stdout_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.CBOR", testValidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidPAKPub, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.CBOR",
			"--key=es256.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CheckCmd_claims_to_file_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.CBOR", testValidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidPAKPub, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.CBOR",
			"--key=es256.jwk",
			"--claims=claims.json",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)

	_, err = fs.Stat("claims.json")
	assert.NoError(t, err)
}

func Test_CheckCmd_claims_to_file_fail(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.CBOR", testValidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidPAKPub, 0644)
	require.NoError(t, err)

	// freeze the FS so that writing is not possible any more
	fs = afero.NewReadOnlyFs(fs)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.CBOR",
			"--key=es256.jwk",
			"--claims=claims.json",
		},
	)

	expectedErr := `error saving CCA attestation claims to file claims.json: operation not permitted`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_key_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.CBOR", testValidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.CBOR",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error decoding verification key from es256.jwk: failed to parse key: invalid key type from JSON ()`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_key_mismatch(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.CBOR", testValidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidRAKPub, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.CBOR",
			"--key=es256.jwk",
		},
	)

	expectedErr := `verifying CCA evidence from ccatoken.CBOR using key from es256.jwk: unable to verify platform token: verification error`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testValidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error loading verification key from es256.jwk: open es256.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_token_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidPAKPub, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `loading CCA evidence from ccatoken.cbor: open ccatoken.cbor: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_token_invalid_format(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testInvalidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidPAKPub, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `loading CCA evidence from ccatoken.cbor: CBOR decoding of CCA evidence failed: unexpected EOF`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_regression_bug_18(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testValidCCAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "not-a-public-key.jwk", testValidPAK, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.cbor",
			"--key=not-a-public-key.jwk",
		},
	)

	expectedErr := `verifying CCA evidence from ccatoken.cbor using key from not-a-public-key.jwk: unable to verify platform token: unable to instantiate verifier: ES256: algorithm mismatch`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
