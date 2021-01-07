/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

func NewFakeCertificatesPathStore() *models.CertificatesPathStore {
	// For ECA, to read list of certificates from directory
	ecCaPath := "../domain/mocks/resources/"
	// Mock path to create new certificate
	rootCaPath := "../domain/mocks/resources/"
	//Path for any certificate containing file, so instead of creating new use existing one
	caCertPath := "../domain/mocks/resources/EndorsementCA-external.pem"

	return &models.CertificatesPathStore{
		models.CaCertTypesRootCa.String(): models.CertLocation{
			CertPath: rootCaPath,
		},
		models.CaCertTypesEndorsementCa.String(): models.CertLocation{
			CertPath: ecCaPath,
		},
		models.CaCertTypesPrivacyCa.String(): models.CertLocation{
			CertPath: caCertPath,
		},
		models.CaCertTypesTagCa.String(): models.CertLocation{
			CertPath: caCertPath,
		},
		models.CertTypesSaml.String(): models.CertLocation{
			CertPath: caCertPath,
		},
		models.CertTypesTls.String(): models.CertLocation{
			CertPath: caCertPath,
		},
	}
}

func NewFakeCertificatesStore() *models.CertificatesStore {

	// Mock path to create new certificate
	rootCaPath := "../domain/mocks/resources/"
	//Path for any certificate containing file, so instead of creating new use existing one
	caCertPath := "../domain/mocks/resources/EndorsementCA-external.pem"

	return &models.CertificatesStore{
		models.CaCertTypesRootCa.String(): &models.CertificateStore{
			CertPath:     rootCaPath,
			Certificates: nil,
		},
		models.CaCertTypesEndorsementCa.String(): &models.CertificateStore{
			CertPath:     rootCaPath,
			Certificates: nil,
		},
		models.CaCertTypesPrivacyCa.String(): &models.CertificateStore{
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CaCertTypesTagCa.String(): &models.CertificateStore{
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CertTypesSaml.String(): &models.CertificateStore{
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CertTypesTls.String(): &models.CertificateStore{
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CertTypesFlavorSigning.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     caCertPath,
			Certificates: nil,
		},
	}
}
