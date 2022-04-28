// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import "github.com/veraison/apiclient/verification"

type IVeraisonClient interface {
	Run() ([]byte, error)
	SetNonce(nonce []byte) error
	SetSessionURI(u string) error
	SetEvidenceBuilder(eb verification.EvidenceBuilder) error
	SetDeleteSession(v bool)
	SetNonceSz(nonceSz uint) error
}
