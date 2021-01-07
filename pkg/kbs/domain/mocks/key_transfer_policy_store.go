/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	log "github.com/sirupsen/logrus"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

// MockKeyTransferPolicyStore provides a mocked implementation of interface domain.KeyTransferPolicyStore
type MockKeyTransferPolicyStore struct {
	KeyTransferPolicyStore map[uuid.UUID]*kbs.KeyTransferPolicyAttributes
}

// Create inserts a KeyTransferPolicy into the store
func (store *MockKeyTransferPolicyStore) Create(p *kbs.KeyTransferPolicyAttributes) (*kbs.KeyTransferPolicyAttributes, error) {
	store.KeyTransferPolicyStore[p.ID] = p
	return p, nil
}

// Retrieve returns a single KeyTransferPolicy record from the store
func (store *MockKeyTransferPolicyStore) Retrieve(id uuid.UUID) (*kbs.KeyTransferPolicyAttributes, error) {
	if p, ok := store.KeyTransferPolicyStore[id]; ok {
		return p, nil
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Delete deletes KeyTransferPolicy from the store
func (store *MockKeyTransferPolicyStore) Delete(id uuid.UUID) error {
	if _, ok := store.KeyTransferPolicyStore[id]; ok {
		delete(store.KeyTransferPolicyStore, id)
		return nil
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a filtered list of KeyTransferPolicies per the provided KeyTransferPolicyFilterCriteria
func (store *MockKeyTransferPolicyStore) Search(criteria *models.KeyTransferPolicyFilterCriteria) ([]kbs.KeyTransferPolicyAttributes, error) {

	var policies []kbs.KeyTransferPolicyAttributes
	// start with all records
	for _, p := range store.KeyTransferPolicyStore {
		policies = append(policies, *p)
	}

	// KeyTransferPolicy filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.KeyTransferPolicyFilterCriteria{}) {
		return policies, nil
	}

	return policies, nil
}

// NewFakeKeyTransferPolicyStore loads dummy data into MockKeyTransferPolicyStore
func NewFakeKeyTransferPolicyStore() *MockKeyTransferPolicyStore {
	store := &MockKeyTransferPolicyStore{}
	store.KeyTransferPolicyStore = make(map[uuid.UUID]*kbs.KeyTransferPolicyAttributes)

	_, err := store.Create(&kbs.KeyTransferPolicyAttributes{
		ID:                                     uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:                              time.Now().UTC(),
		SGXEnclaveIssuerAnyof:                  []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
		SGXEnclaveIssuerProductIDAnyof:         []int16{0},
		SGXEnclaveIssuerExtendedProductIDAnyof: []string{"00000000000000000000000000000000"},
		SGXEnclaveMeasurementAnyof:             []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
		SGXConfigIDAnyof:                       []string{"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		SGXEnclaveSVNMinimum:                   int16(1),
		TLSClientCertificateIssuerCNAnyof:      []string{"CMSCA", "CMS TLS Client CA"},
		AttestationTypeAnyof:                   []string{"SGX"},
		TLSClientCertificateSANAllof:           []string{"nginx", "USA"},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer properties")
	}

	_, err = store.Create(&kbs.KeyTransferPolicyAttributes{
		ID:                                     uuid.MustParse("73755fda-c910-46be-821f-e8ddeab189e9"),
		CreatedAt:                              time.Now().UTC(),
		SGXEnclaveIssuerAnyof:                  []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
		SGXEnclaveIssuerProductIDAnyof:         []int16{0},
		SGXEnclaveIssuerExtendedProductIDAnyof: []string{"00000000000000000000000000000000"},
		SGXEnclaveMeasurementAnyof:             []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
		SGXConfigIDAnyof:                       []string{"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		SGXEnclaveSVNMinimum:                   int16(1),
		TLSClientCertificateIssuerCNAnyof:      []string{"CMSCA", "CMS TLS Client CA"},
		AttestationTypeAnyof:                   []string{"SGX"},
		TLSClientCertificateSANAllof:           []string{"nginx", "USA"},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer properties")
	}

	return store
}
