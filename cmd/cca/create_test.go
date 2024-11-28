// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CreateCmd_default_token_name_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)

	_, err = fs.Stat("claims.cbor")
	assert.NoError(t, err)
}

func Test_CreateCmd_custom_token_name_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
			"--token=my.cbor",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)

	_, err = fs.Stat("my.cbor")
	assert.NoError(t, err)
}

func Test_CreateCmd_save_token_fail(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	// freeze the FS so that writing is not possible any more
	fs = afero.NewReadOnlyFs(fs)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error saving CCA attestation token to file claims.cbor: operation not permitted`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_RAK_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error decoding RAK signing key from es384.jwk: failed to parse key: invalid key type from JSON ()`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_RAK_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error loading RAK signing key from es384.jwk: open es384.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_IAK_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error decoding IAK signing key from es256.jwk: failed to parse key: invalid key type from JSON ()`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_IAK_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error loading IAK signing key from es256.jwk: open es256.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_claims_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error loading CCA claims from claims.json: open claims.json: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_claims_invalid(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidIAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidRAK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testInvalidCCAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--iak=es256.jwk",
			"--rak=es384.jwk",
		},
	)

	expectedErr := `error loading CCA claims from claims.json: claims not set in evidence`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
