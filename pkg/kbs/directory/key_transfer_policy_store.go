/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package directory

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type KeyTransferPolicyStore struct {
	dir string
}

func NewKeyTransferPolicyStore(dir string) *KeyTransferPolicyStore {
	return &KeyTransferPolicyStore{dir}
}

func (ktps *KeyTransferPolicyStore) Create(policy *kbs.KeyTransferPolicyAttributes) (*kbs.KeyTransferPolicyAttributes, error) {
	defaultLog.Trace("directory/key_transfer_policy_store:Create() Entering")
	defer defaultLog.Trace("directory/key_transfer_policy_store:Create() Leaving")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Create() failed to create new UUID")
	}
	policy.ID = newUuid
	policy.CreatedAt = time.Now().UTC()
	bytes, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Create() Failed to marshal key transfer policy")
	}

	err = ioutil.WriteFile(filepath.Join(ktps.dir, policy.ID.String()), bytes, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Create() Error in saving key transfer policy")
	}

	return policy, nil
}

func (ktps *KeyTransferPolicyStore) Retrieve(id uuid.UUID) (*kbs.KeyTransferPolicyAttributes, error) {
	defaultLog.Trace("directory/key_transfer_policy_store:Retrieve() Entering")
	defer defaultLog.Trace("directory/key_transfer_policy_store:Retrieve() Leaving")

	bytes, err := ioutil.ReadFile(filepath.Join(ktps.dir, id.String()))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New(commErr.RecordNotFound)
		} else {
			return nil, errors.Wrapf(err, "directory/key_transfer_policy_store:Retrieve() Unable to read key transfer policy file : %s", id.String())
		}
	}

	var policy kbs.KeyTransferPolicyAttributes
	err = json.Unmarshal(bytes, &policy)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_transfer_policy_store:Retrieve() Failed to unmarshal key transfer policy")
	}

	return &policy, nil
}

func (ktps *KeyTransferPolicyStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("directory/key_transfer_policy_store:Delete() Entering")
	defer defaultLog.Trace("directory/key_transfer_policy_store:Delete() Leaving")

	if err := os.Remove(filepath.Join(ktps.dir, id.String())); err != nil {
		if os.IsNotExist(err) {
			return errors.New(commErr.RecordNotFound)
		} else {
			return errors.Wrapf(err, "directory/key_transfer_policy_store:Delete() Unable to remove key transfer policy file : %s", id.String())
		}
	}

	return nil
}

func (ktps *KeyTransferPolicyStore) Search(criteria *models.KeyTransferPolicyFilterCriteria) ([]kbs.KeyTransferPolicyAttributes, error) {
	defaultLog.Trace("directory/key_transfer_policy_store:Search() Entering")
	defer defaultLog.Trace("directory/key_transfer_policy_store:Search() Leaving")

	var policies = []kbs.KeyTransferPolicyAttributes{}
	policyFiles, err := ioutil.ReadDir(ktps.dir)
	if err != nil {
		return nil, errors.New("directory/key_transfer_policy_store:Search() Unable to read the key transfer policy directory")
	}

	for _, policyFile := range policyFiles {
		filename, err := uuid.Parse(policyFile.Name())
		if err != nil {
			return nil, errors.Wrapf(err, "directory/key_transfer_policy_store:Search() Error in parsing policy file name : %s", policyFile.Name())
		}
		policy, err := ktps.Retrieve(filename)
		if err != nil {
			return nil, errors.Wrapf(err, "directory/key_transfer_policy_store:Search() Error in retrieving policy from file : %s", policyFile.Name())
		}

		policies = append(policies, *policy)
	}

	if len(policies) > 0 {
		policies = filterKeyTransferPolicies(policies, criteria)
	}

	return policies, nil
}

// helper function to filter the key transfer policies based on given filter criteria.
func filterKeyTransferPolicies(policies []kbs.KeyTransferPolicyAttributes, criteria *models.KeyTransferPolicyFilterCriteria) []kbs.KeyTransferPolicyAttributes {
	defaultLog.Trace("directory/key_transfer_policy_store:filterKeyTransferPolicies() Entering")
	defer defaultLog.Trace("directory/key_transfer_policy_store:filterKeyTransferPolicies() Leaving")

	if criteria == nil || reflect.DeepEqual(*criteria, models.KeyTransferPolicyFilterCriteria{}) {
		return policies
	}
	return policies
}
