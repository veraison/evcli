// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CheckCmd_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testValidPSAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CheckCmd_token_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `open psatoken.cbor: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testValidPSAToken, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error loading verification key from es256.jwk: open es256.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_claims_file_write_failed(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testValidPSAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	// freeze the FS so that writing is not possible anymore
	fs = afero.NewReadOnlyFs(fs)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
			"--claims=nonexistent/claims.json",
		},
	)

	expectedErr := `error saving PSA attesation claims to file nonexistent/claims.json: operation not permitted`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_bad_key(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testValidPSAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error decoding verification key from es256.jwk: failed to parse key`

	err = cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}

func Test_CheckCmd_bad_token(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testInvalidPSAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `the supplied CWT is not a COSE-Sign1 message`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CheckCmd_bad_signature(t *testing.T) {
	fs := afero.NewMemMapFs()

	tamperedPSAToken := testValidPSAToken
	tamperedPSAToken[len(tamperedPSAToken)-1] ^= 1

	err := afero.WriteFile(fs, "psatoken.cbor", tamperedPSAToken, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCheckCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
			"--key=es256.jwk",
		},
	)

	expectedErr := `signature verification failed: verification failed ecdsa.Verify`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
