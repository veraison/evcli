// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrintCmd_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testValidP2PSAToken, 0644)
	require.NoError(t, err)

	cmd := NewPrintCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_PrintCmd_token_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	cmd := NewPrintCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
		},
	)

	expectedErr := `open psatoken.cbor: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_PrintCmd_bad_token(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "psatoken.cbor", testInvalidPSAToken, 0644)
	require.NoError(t, err)

	cmd := NewPrintCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=psatoken.cbor",
		},
	)

	expectedErr := `failed CBOR decoding for CWT: cbor: invalid COSE_Sign1_Tagged object`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
