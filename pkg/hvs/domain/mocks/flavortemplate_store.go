/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"fmt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockFlavorTemplateStore provides a mocked implementation of interface hvs.FlavorTemplate
type MockFlavorTemplateStore struct {
	FlavorTemplateStore []hvs.FlavorTemplate
	DeletedTemplatesStore []hvs.FlavorTemplate
}

var flavorTemplate = `{
	"id": "426912bd-39b0-4daa-ad21-0c6933230b50",
	"label": "default-uefi",
	"condition": [
		"//host_info/vendor='Linux'",
		"//host_info/tpm_version='2.0'",
		"//host_info/uefi_enabled='true'",
		"//host_info/suefi_enabled='true'"
	],
	"flavor_parts": {
		"PLATFORM": {
			"meta": {
				"tpm_version": "2.0",
				"uefi_enabled": true,
				"vendor": "Linux"
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 0,
						"bank": "SHA256"
					},
					"pcr_matches": true,
					"eventlog_equals": {}
				}
			]
		},
		"OS": {
			"meta": {
				"tpm_version": "2.0",
				"uefi_enabled": true,
				"vendor": "Linux"
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 7,
						"bank": "SHA256"
					},
					"pcr_matches": true,
					"eventlog_includes": [
						"shim",
						"db",
						"kek",
						"vmlinuz"
					]
				}
			]
		}
	}
}`

// Create and inserts a Flavortemplate
func (store *MockFlavorTemplateStore) Create(ft *hvs.FlavorTemplate) (*hvs.FlavorTemplate, error) {

	if ft.ID == uuid.Nil {
		ft.ID = uuid.New()
	}

	rec := hvs.FlavorTemplate{
		ID:          ft.ID,
		Condition:   ft.Condition,
		Label:       ft.Label,
		FlavorParts: ft.FlavorParts,
	}
	store.FlavorTemplateStore = append(store.FlavorTemplateStore, rec)

	return &rec, nil
}

// Retrieve a Flavortemplate
func (store *MockFlavorTemplateStore) Retrieve(templateID uuid.UUID) (*hvs.FlavorTemplate, error) {
	rec := hvs.FlavorTemplate{}
	return &rec, nil
}

// Search a Flavortemplate(s)
func (store *MockFlavorTemplateStore) Search(includeDeleted bool) ([]hvs.FlavorTemplate, error) {
	rec := store.FlavorTemplateStore
	if includeDeleted {
		rec = append(rec,store.DeletedTemplatesStore...)
	}
	return rec, nil
}

// Detele a Flavortemplate
func (store *MockFlavorTemplateStore) Delete(templateID uuid.UUID) error {
	flavorTemplates := store.FlavorTemplateStore
	for i, template := range flavorTemplates {
		if template.ID == templateID {
			store.DeletedTemplatesStore = append(store.DeletedTemplatesStore,template)
			store.FlavorTemplateStore[i] = store.FlavorTemplateStore[len(store.FlavorTemplateStore)-1]
			store.FlavorTemplateStore = store.FlavorTemplateStore[:len(store.FlavorTemplateStore)-1]
			return nil
		}
	}
	return errors.New(commErr.RowsNotFound)
}

// Recover a Flavortemplate
func (store *MockFlavorTemplateStore) Recover(labels []string) error {
	return nil
}

// NewFakeFlavorTemplateStore provides two dummy data for FlavorTemplates
func NewFakeFlavorTemplateStore() *MockFlavorTemplateStore {
	store := &MockFlavorTemplateStore{}

	var sf hvs.FlavorTemplate
	err := json.Unmarshal([]byte(flavorTemplate), &sf)
	fmt.Println("error: ", err)

	// add to store
	store.Create(&sf)

	return store
}
