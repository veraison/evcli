// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrintCmd_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.CBOR", testValidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewPrintCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.CBOR",
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
			"--token=ccatoken.cbor",
		},
	)

	expectedErr := `loading CCA evidence from ccatoken.cbor: open ccatoken.cbor: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_PrintCmd_token_invalid_format(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "ccatoken.cbor", testInvalidCCAToken, 0644)
	require.NoError(t, err)

	cmd := NewPrintCmd(fs)
	cmd.SetArgs(
		[]string{
			"--token=ccatoken.cbor",
		},
	)

	expectedErr := `loading CCA evidence from ccatoken.cbor: CBOR decoding of CCA evidence failed: unexpected EOF`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
