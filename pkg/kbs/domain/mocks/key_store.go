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
	"github.com/pkg/errors"
)

// MockKeyStore provides a mocked implementation of interface domain.KeyStore
type MockKeyStore struct {
	KeyStore map[uuid.UUID]*models.KeyAttributes
}

// Create inserts a Key into the store
func (store *MockKeyStore) Create(k *models.KeyAttributes) (*models.KeyAttributes, error) {
	store.KeyStore[k.ID] = k
	return k, nil
}

// Retrieve returns a single Key record from the store
func (store *MockKeyStore) Retrieve(id uuid.UUID) (*models.KeyAttributes, error) {
	if k, ok := store.KeyStore[id]; ok {
		return k, nil
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Delete deletes Key from the store
func (store *MockKeyStore) Delete(id uuid.UUID) error {
	if _, ok := store.KeyStore[id]; ok {
		delete(store.KeyStore, id)
		return nil
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a filtered list of Keys per the provided KeyFilterCriteria
func (store *MockKeyStore) Search(criteria *models.KeyFilterCriteria) ([]models.KeyAttributes, error) {

	var keys []models.KeyAttributes
	// start with all records
	for _, k := range store.KeyStore {
		keys = append(keys, *k)
	}

	// Key filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.KeyFilterCriteria{}) {
		return keys, nil
	}

	// Algorithm filter
	if criteria.Algorithm != "" {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.Algorithm == criteria.Algorithm {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// KeyLength filter
	if criteria.KeyLength != 0 {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.KeyLength == criteria.KeyLength {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// CurveType filter
	if criteria.CurveType != "" {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.CurveType == criteria.CurveType {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	// TransferPolicyId filter
	if criteria.TransferPolicyId != uuid.Nil {
		var kFiltered []models.KeyAttributes
		for _, k := range keys {
			if k.TransferPolicyId == criteria.TransferPolicyId {
				kFiltered = append(kFiltered, k)
			}
		}
		keys = kFiltered
	}

	return keys, nil
}

// NewFakeKeyStore loads dummy data into MockKeyStore
func NewFakeKeyStore() *MockKeyStore {
	store := &MockKeyStore{}
	store.KeyStore = make(map[uuid.UUID]*models.KeyAttributes)

	_, err := store.Create(&models.KeyAttributes{
		ID:               uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Algorithm:        "AES",
		KeyLength:        256,
		KeyData:          "",
		KmipKeyID:        "1",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "https://localhost:9443/kbs/v1/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key attributes")
	}

	_, err = store.Create(&models.KeyAttributes{
		ID:               uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Algorithm:        "EC",
		CurveType:        "prime256v1",
		PublicKey:        "",
		PrivateKey:       "",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "https://localhost:9443/kbs/v1/keys/e57e5ea0-d465-461e-882d-1600090caa0d/transfer",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key attributes")
	}

	return store
}
