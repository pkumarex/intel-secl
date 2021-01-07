/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package saml

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

const (
	sampleValidSamlCertPath         = "test/resources/saml_certificate.pem"
	sampleValidSamlReportPath       = "test/resources/saml_report.xml"
	sampleInvalidSamlReportPath     = "test/resources/invalid_saml_report.xml"
	sampleInvalidSamlWithoutSigPath = "test/resources/invalid_saml_without_sig.xml"
	sampleInvalidSamlCertPath       = "test/resources/invalid_samlCert.pem"
	sampleRootCertDirPath           = "test/resources/trustedCACert"
)

func TestSAMLSignatureVerification(t *testing.T) {

	// validate
	reportBytes, _ := ioutil.ReadFile(sampleValidSamlReportPath)
	trusted := VerifySamlSignature(string(reportBytes), sampleValidSamlCertPath, sampleRootCertDirPath)
	assert.Equal(t, trusted, true)
}

func TestSAMLSignatureVerificationForInvalidCertificate(t *testing.T) {

	// validate
	reportBytes, _ := ioutil.ReadFile(sampleValidSamlCertPath)
	trusted := VerifySamlSignature(string(reportBytes), sampleInvalidSamlCertPath, sampleRootCertDirPath)
	assert.Equal(t, trusted, false)
}

func TestSAMLSignatureVerificationForExpiredReport(t *testing.T) {

	// validate
	reportBytes, _ := ioutil.ReadFile(sampleInvalidSamlReportPath)
	trusted := VerifySamlSignature(string(reportBytes), sampleValidSamlCertPath, sampleRootCertDirPath)
	assert.Equal(t, trusted, false)
}

func TestSAMLVerificationWithoutSignature(t *testing.T) {

	// validate
	reportBytes, _ := ioutil.ReadFile(sampleInvalidSamlWithoutSigPath)
	trusted := VerifySamlSignature(string(reportBytes), sampleValidSamlCertPath, sampleRootCertDirPath)
	assert.Equal(t, trusted, false)
}
