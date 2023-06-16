// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ptpm

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CreateCmd_default_token_name_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidCK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es384.jwk", testValidSK, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidParsectpmClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--ck=es256.jwk",
			"--sk=es384.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)

	_, err = fs.Stat("claims.cbor")
	assert.NoError(t, err)
}
