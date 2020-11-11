/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
)

type RemoteManager struct {
	store       domain.KeyStore
	manager     KeyManager
	endpointURL string
}

func NewRemoteManager(ks domain.KeyStore, km KeyManager, url string) *RemoteManager {
	return &RemoteManager{
		store:       ks,
		manager:     km,
		endpointURL: url,
	}
}

func (rm *RemoteManager) CreateKey(request *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:CreateKey() Leaving")

	keyAttributes, err := rm.manager.CreateKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = rm.getTransferLink(keyAttributes.ID)
	storedKey, err := rm.store.Create(keyAttributes)
	if err != nil {
		return nil, err
	}

	return storedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) RetrieveKey(keyId uuid.UUID) (*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:RetrieveKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:RetrieveKey() Leaving")

	keyAttributes, err := rm.store.Retrieve(keyId)
	if err != nil {
		return nil, err
	}

	return keyAttributes.ToKeyResponse(), nil
}

func (rm *RemoteManager) DeleteKey(keyId uuid.UUID) error {
	defaultLog.Trace("keymanager/remote_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:DeleteKey() Leaving")

	keyAttributes, err := rm.store.Retrieve(keyId)
	if err != nil {
		return err
	}

	if err := rm.manager.DeleteKey(keyAttributes); err != nil {
		return err
	}

	return rm.store.Delete(keyId)
}

func (rm *RemoteManager) SearchKeys(criteria *models.KeyFilterCriteria) ([]*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:SearchKeys() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:SearchKeys() Leaving")

	keyAttributesList, err := rm.store.Search(criteria)
	if err != nil {
		return nil, err
	}

	var keyResponses = []*kbs.KeyResponse{}
	for _, keyAttributes := range keyAttributesList {
		keyResponses = append(keyResponses, keyAttributes.ToKeyResponse())
	}

	return keyResponses, nil
}

func (rm *RemoteManager) RegisterKey(request *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:RegisterKey() Leaving")

	keyAttributes, err := rm.manager.RegisterKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = rm.getTransferLink(keyAttributes.ID)
	storedKey, err := rm.store.Create(keyAttributes)
	if err != nil {
		return nil, err
	}

	return storedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) TransferKey(keyId uuid.UUID) ([]byte, error) {
	defaultLog.Trace("keymanager/remote_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:TransferKey() Leaving")

	keyAttributes, err := rm.store.Retrieve(keyId)
	if err != nil {
		return nil, err
	}

	return rm.manager.TransferKey(keyAttributes)
}

func (rm *RemoteManager) getTransferLink(keyId uuid.UUID) string {
	defaultLog.Trace("keymanager/remote_key_manager:getTransferLink() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:getTransferLink() Leaving")
	if strings.HasSuffix(rm.endpointURL, "/") {
		return fmt.Sprintf("%skeys/%s/transfer", rm.endpointURL, keyId.String())
	} else {
		return fmt.Sprintf("%s/keys/%s/transfer", rm.endpointURL, keyId.String())
	}
}
