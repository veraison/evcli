// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CreateCmd_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CreateCmd_WithP1Claims_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidP1PSAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
			"--profile=PSA_IOT_PROFILE_1",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CreateCmd_claims_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `open claims.json: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error loading signing key from es256.jwk: open es256.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_token_file_write_failed(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	// freeze the FS so that writing is not possible anymore
	fs = afero.NewReadOnlyFs(fs)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--key=es256.jwk",
			"--claims=claims.json",
		},
	)

	expectedErr := `error saving PSA attesation token to file claims.cbor: operation not permitted`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_claims_profile_mismatch(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--key=es256.jwk",
			"--claims=claims.json",
			"--profile=PSA_IOT_PROFILE_1",
		},
	)

	expectedErr := `profile mismatch input: PSA_IOT_PROFILE_1 and created: http://arm.com/psa/2.0.0`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_unknown_profile(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--key=es256.jwk",
			"--claims=claims.json",
			"--profile=UNKNOWN_PROFILE_3",
		},
	)

	expectedErr := `wrong profile UNKNOWN_PROFILE_3: allowed profiles are http://arm.com/psa/2.0.0 and PSA_IOT_PROFILE_1`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_bad_key(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error decoding signing key from es256.jwk: failed to parse key`

	err = cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}
