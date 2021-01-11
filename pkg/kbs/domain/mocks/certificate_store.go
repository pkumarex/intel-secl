/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

const (
	samlCertPath        = "./resources/saml/saml_cert.pem"
	tpmIdentityCertPath = "./resources/tpm-identity/privacyca_cert.pem"
)

// MockCertificateStore provides a mocked implementation of interface domain.CertificateStore
type MockCertificateStore struct {
	CertificateStore map[uuid.UUID]*kbs.Certificate
}

// Create inserts a Certificate into the store
func (store *MockCertificateStore) Create(c *kbs.Certificate) (*kbs.Certificate, error) {
	store.CertificateStore[c.ID] = c
	return c, nil
}

// Retrieve returns a single Certificate record from the store
func (store *MockCertificateStore) Retrieve(id uuid.UUID) (*kbs.Certificate, error) {
	if c, ok := store.CertificateStore[id]; ok {
		return c, nil
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Delete deletes Certificate from the store
func (store *MockCertificateStore) Delete(id uuid.UUID) error {
	if _, ok := store.CertificateStore[id]; ok {
		delete(store.CertificateStore, id)
		return nil
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a filtered list of Certificates per the provided CertificateFilterCriteria
func (store *MockCertificateStore) Search(criteria *models.CertificateFilterCriteria) ([]kbs.Certificate, error) {

	var certs []kbs.Certificate
	// start with all records
	for _, c := range store.CertificateStore {
		certs = append(certs, *c)
	}

	// Certificate filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.CertificateFilterCriteria{}) {
		return certs, nil
	}

	// SubjectEqualTo filter
	if criteria.SubjectEqualTo != "" {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if c.Subject == criteria.SubjectEqualTo {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	// SubjectContains filter
	if criteria.SubjectContains != "" {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if strings.Contains(c.Subject, criteria.SubjectContains) {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	// IssuerEqualTo filter
	if criteria.IssuerEqualTo != "" {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if strings.ToLower(c.Issuer) == strings.ToLower(criteria.IssuerEqualTo) {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	// IssuerContains filter
	if criteria.IssuerContains != "" {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if strings.Contains(strings.ToLower(c.Issuer), strings.ToLower(criteria.IssuerContains)) {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	// ValidOn filter
	if !criteria.ValidOn.IsZero() {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if c.NotBefore.Before(criteria.ValidOn) && c.NotAfter.After(criteria.ValidOn) {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	// ValidAfter filter
	if !criteria.ValidAfter.IsZero() {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if c.NotBefore.After(criteria.ValidAfter) {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	// ValidBefore filter
	if !criteria.ValidBefore.IsZero() {
		var cFiltered []kbs.Certificate
		for _, c := range certs {
			if c.NotAfter.Before(criteria.ValidBefore) {
				cFiltered = append(cFiltered, c)
			}
		}
		certs = cFiltered
	}

	return certs, nil
}

// NewFakeCertificateStore loads dummy data into MockCertificateStore
func NewFakeCertificateStore() *MockCertificateStore {
	store := &MockCertificateStore{}
	store.CertificateStore = make(map[uuid.UUID]*kbs.Certificate)

	certPem, _ := ioutil.ReadFile(samlCertPath)
	cert, _ := crypt.GetCertFromPem(certPem)

	_, err := store.Create(&kbs.Certificate{
		ID:          uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Certificate: certPem,
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   &cert.NotBefore,
		NotAfter:    &cert.NotAfter,
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating certificate")
	}

	certPem, _ = ioutil.ReadFile(tpmIdentityCertPath)
	cert, _ = crypt.GetCertFromPem(certPem)

	_, err = store.Create(&kbs.Certificate{
		ID:          uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Certificate: certPem,
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   &cert.NotBefore,
		NotAfter:    &cert.NotAfter,
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating certificate")
	}

	return store
}
