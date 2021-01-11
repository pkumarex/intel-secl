/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"crypto"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
)

func LoadCertificates(certificatePaths *models.CertificatesPathStore) *models.CertificatesStore {
	defaultLog.Trace("utils/certificate_store:LoadCertificates() Entering")
	defer defaultLog.Trace("utils/certificate_store:LoadCertificates() Leaving")

	certificateStore := make(models.CertificatesStore)
	for _, certType := range models.GetUniqueCertTypes() {
		certloc := (*certificatePaths)[certType]
		if certType == models.CaCertTypesRootCa.String() || certType == models.CaCertTypesEndorsementCa.String() {
			certificateStore[certType] = loadCertificatesFromDir(&certloc)
		} else {
			certificateStore[certType] = loadCertificatesFromFile(&certloc)
		}
	}
	defaultLog.Debug("utils/certificate_store:LoadCertificates() Loaded certificates")
	for _, certType := range models.GetUniqueCertTypes() {
		defaultLog.Debugf("utils/certificate_store:LoadCertificates() Certificates loaded for type - %s", certType)
		certStore := certificateStore[certType]
		if certStore != nil && certStore.Certificates != nil {
			for _, cert := range certStore.Certificates {
				defaultLog.Debugf("utils/certificate_store:LoadCertificates() Certificate CN - %s", cert.Subject.CommonName)
			}
		}
	}
	return &certificateStore
}

func loadCertificatesFromFile(certLocation *models.CertLocation) *models.CertificateStore {
	defaultLog.Trace("utils/certificate_store:loadCertificatesFromFile() Entering")
	defer defaultLog.Trace("utils/certificate_store:loadCertificatesFromFile() Leaving")

	certs, err := crypt.GetSubjectCertsMapFromPemFile(certLocation.CertPath)
	if err != nil {
		defaultLog.WithError(err).Errorf("utils/certificate_store:loadCertificatesFromFile() Error while reading certs from file - " + certLocation.CertPath)
	}

	key := loadKey(certLocation.KeyFile)
	return &models.CertificateStore{
		Key:          key,
		CertPath:     certLocation.CertPath,
		Certificates: certs,
	}
}

func loadCertificatesFromDir(certLocation *models.CertLocation) *models.CertificateStore {
	defaultLog.Trace("utils/certificate_store:loadCertificatesFromDir() Entering")
	defer defaultLog.Trace("utils/certificate_store:loadCertificatesFromDir() Leaving")

	certificates, err := crypt.GetCertsFromDir(certLocation.CertPath)
	if err != nil {
		defaultLog.WithError(err).Warnf("utils/certificate_store:loadCertificatesFromDir() Error while reading certificates from " + certLocation.CertPath)
	}
	key := loadKey(certLocation.KeyFile)
	return &models.CertificateStore{
		Key:          key,
		CertPath:     certLocation.CertPath,
		Certificates: certificates,
	}
}

func loadKey(keyFile string) crypto.PrivateKey {
	defaultLog.Trace("utils/certificate_store:loadKey() Entering")
	defer defaultLog.Trace("utils/certificate_store:loadKey() Leaving")

	if keyFile == "" {
		return nil
	}
	key, err := crypt.GetPrivateKeyFromPKCS8File(keyFile)
	if err != nil {
		defaultLog.WithError(err).Errorf("utils/certificate_store:loadKey() Error while reading key from file - " + keyFile)
	}
	return key
}
