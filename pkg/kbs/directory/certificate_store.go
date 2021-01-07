/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package directory

import (
	"crypto/sha512"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()

type CertificateStore struct {
	dir string
}

func NewCertificateStore(dir string) *CertificateStore {
	return &CertificateStore{dir}
}

func (cs *CertificateStore) Create(certificate *kbs.Certificate) (*kbs.Certificate, error) {
	defaultLog.Trace("directory/certificate_store:Create() Entering")
	defer defaultLog.Trace("directory/certificate_store:Create() Leaving")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "directory/certificate_store:Create() failed to create new UUID")
	}
	certificate.ID = newUuid
	err = ioutil.WriteFile(filepath.Join(cs.dir, certificate.ID.String()), certificate.Certificate, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "directory/certificate_store:Create() Failed to store certificate")
	}

	return certificate, nil
}

func (cs *CertificateStore) Retrieve(id uuid.UUID) (*kbs.Certificate, error) {
	defaultLog.Trace("directory/certificate_store:Retrieve() Entering")
	defer defaultLog.Trace("directory/certificate_store:Retrieve() Leaving")

	certPem, err := ioutil.ReadFile(filepath.Join(cs.dir, id.String()))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New(commErr.RecordNotFound)
		} else {
			return nil, errors.Wrapf(err, "directory/certificate_store:Retrieve() Unable to read certificate file : %s", id.String())
		}
	}

	cert, err := crypt.GetCertFromPem(certPem)
	if err != nil {
		return nil, errors.Wrapf(err, "directory/certificate_store:Retrieve() Error in decoding the certificate")
	}

	fingerprint := sha512.Sum384(cert.Raw)
	certificate := &kbs.Certificate{
		ID:          id,
		Certificate: certPem,
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   &cert.NotBefore,
		NotAfter:    &cert.NotAfter,
		Revoked:     false,
		Digest:      hex.EncodeToString(fingerprint[:]),
	}

	return certificate, nil
}

func (cs *CertificateStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("directory/certificate_store:Delete() Entering")
	defer defaultLog.Trace("directory/certificate_store:Delete() Leaving")

	if err := os.Remove(filepath.Join(cs.dir, id.String())); err != nil {
		if os.IsNotExist(err) {
			return errors.New(commErr.RecordNotFound)
		} else {
			return errors.Wrapf(err, "directory/certificate_store:Delete() Unable to remove certificate file : %s", id.String())
		}
	}

	return nil
}

func (cs *CertificateStore) Search(criteria *models.CertificateFilterCriteria) ([]kbs.Certificate, error) {
	defaultLog.Trace("directory/certificate_store:Search() Entering")
	defer defaultLog.Trace("directory/certificate_store:Search() Leaving")

	var certificates = []kbs.Certificate{}
	certFiles, err := ioutil.ReadDir(cs.dir)
	if err != nil {
		return nil, errors.Wrapf(err, "directory/certificate_store:Search() Error in reading the certificates directory : %s", cs.dir)
	}

	for _, certFile := range certFiles {
		filename, err := uuid.Parse(certFile.Name())
		if err != nil {
			return nil, errors.Wrapf(err, "directory/certificate_store:Search() Error in parsing certificate file name : %s", certFile.Name())
		}
		certificate, err := cs.Retrieve(filename)
		if err != nil {
			return nil, errors.Wrapf(err, "directory/certificate_store:Search() Error in retrieving certificate from file : %s", certFile.Name())
		}

		certificates = append(certificates, *certificate)
	}

	if len(certificates) > 0 {
		certificates = filterCertificates(certificates, criteria)
	}

	return certificates, nil
}

// helper function to filter the certificates based on given filter criteria.
func filterCertificates(certificates []kbs.Certificate, criteria *models.CertificateFilterCriteria) []kbs.Certificate {
	defaultLog.Trace("directory/certificate_store:filterCertificates() Entering")
	defer defaultLog.Trace("directory/certificate_store:filterCertificates() Leaving")

	if criteria == nil || reflect.DeepEqual(*criteria, models.CertificateFilterCriteria{}) {
		return certificates
	}

	// SubjectEqualTo filter
	if criteria.SubjectEqualTo != "" {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if cert.Subject == criteria.SubjectEqualTo {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	// SubjectContains filter
	if criteria.SubjectContains != "" {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if strings.Contains(cert.Subject, criteria.SubjectContains) {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	// IssuerEqualTo filter
	if criteria.IssuerEqualTo != "" {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if strings.ToLower(cert.Issuer) == strings.ToLower(criteria.IssuerEqualTo) {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	// IssuerContains filter
	if criteria.IssuerContains != "" {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if strings.Contains(strings.ToLower(cert.Issuer), strings.ToLower(criteria.IssuerContains)) {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	// ValidBefore filter
	if !criteria.ValidBefore.IsZero() {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if cert.NotAfter.Before(criteria.ValidBefore) {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	// ValidAfter filter
	if !criteria.ValidAfter.IsZero() {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if cert.NotBefore.After(criteria.ValidAfter) {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	// ValidOn filter
	if !criteria.ValidOn.IsZero() {
		var filteredCerts []kbs.Certificate
		for _, cert := range certificates {
			if cert.NotBefore.Before(criteria.ValidOn) && cert.NotAfter.After(criteria.ValidOn) {
				filteredCerts = append(filteredCerts, cert)
			}
		}
		certificates = filteredCerts
	}

	return certificates
}
