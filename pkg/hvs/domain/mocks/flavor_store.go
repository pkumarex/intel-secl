/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"io/ioutil"
	"reflect"
)

// MockFlavorStore provides a mocked implementation of interface hvs.FlavorStore
type MockFlavorStore struct {
	flavorStore            []hvs.SignedFlavor
	FlavorFlavorGroupStore map[uuid.UUID][]uuid.UUID
	FlavorgroupStore       map[uuid.UUID]*hvs.FlavorGroup
}

var flavor = ` {
            "flavor": {
                "meta": {
                    "id": "c36b5412-8c02-4e08-8a74-8bfa40425cf3",
                    "description": {
                        "flavor_part": "PLATFORM",
                        "source": "Purley21",
                        "label": "INTEL_IntelCorporation_SE5C620.86B.00.01.0014.070920180847_TXT_TPM_06-16-2020",
                        "bios_name": "IntelCorporation",
                        "bios_version": "SE5C620.86B.00.01.0014.070920180847",
                        "tpm_version": "2.0",
                        "tboot_installed": "true"
                    },
                    "vendor": "INTEL"
                },
                "bios": {
                    "bios_name": "Intel Corporation",
                    "bios_version": "SE5C620.86B.00.01.0014.070920180847"
                },
                "hardware": {
                    "processor_info": "54 06 05 00 FF FB EB BF",
                    "feature": {
                        "tpm": {
                            "enabled": true,
                            "version": "2.0",
                            "pcr_banks": [
                                "SHA1",
                                "SHA256"
                            ]
                        },
                        "txt": {
                            "enabled": true
                        }
                    }
                },
                "pcrs": {
                    "SHA1": {
                        "pcr_0": {
                            "value": "3f95ecbb0bb8e66e54d3f9e4dbae8fe57fed96f0"
                        },
                        "pcr_17": {
                            "value": "460d626473202cb536b37d56dc0fd43438fae165",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "19f7c22f6c92d9555d792466b2097443444ebd26",
                                    "label": "HASH_START",
                                    "info": {
                                        "ComponentName": "HASH_START",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "3cf4a5c90911c21f6ea71f4ca84425f8e65a2be7",
                                    "label": "BIOSAC_REG_DATA",
                                    "info": {
                                        "ComponentName": "BIOSAC_REG_DATA",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "3c585604e87f855973731fea83e21fab9392d2fc",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                                    "label": "LCP_DETAILS_HASH",
                                    "info": {
                                        "ComponentName": "LCP_DETAILS_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                                    "label": "STM_HASH",
                                    "info": {
                                        "ComponentName": "STM_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "ff86d5446b2cc2e7e3319048715c00aabb7dcc4e",
                                    "label": "MLE_HASH",
                                    "info": {
                                        "ComponentName": "MLE_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        },
                        "pcr_18": {
                            "value": "86da61107994a14c0d154fd87ca509f82377aa30",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "a395b723712b3711a89c2bb5295386c0db85fe44",
                                    "label": "SINIT_PUBKEY_HASH",
                                    "info": {
                                        "ComponentName": "SINIT_PUBKEY_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "3c585604e87f855973731fea83e21fab9392d2fc",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                                    "label": "LCP_AUTHORITIES_HASH",
                                    "info": {
                                        "ComponentName": "LCP_AUTHORITIES_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                                    "value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    },
                    "SHA256": {
                        "pcr_0": {
                            "value": "1009d6bc1d92739e4e8e3c6819364f9149ee652804565b83bf731bdb6352b2a6"
                        },
                        "pcr_17": {
                            "value": "c4a4b0b6601abc9756fdc0cecce173e781096e2ca0ce12650951a933821bd772",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "14fc51186adf98be977b9e9b65fc9ee26df0599c4f45804fcc45d0bdcf5025db",
                                    "label": "HASH_START",
                                    "info": {
                                        "ComponentName": "HASH_START",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "c61aaa86c13133a0f1e661faf82e74ba199cd79cef652097e638a756bd194428",
                                    "label": "BIOSAC_REG_DATA",
                                    "info": {
                                        "ComponentName": "BIOSAC_REG_DATA",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                                    "label": "LCP_DETAILS_HASH",
                                    "info": {
                                        "ComponentName": "LCP_DETAILS_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                                    "label": "STM_HASH",
                                    "info": {
                                        "ComponentName": "STM_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "236043f5120fce826392d2170dc84f2491367cc8d8d403ab3b83ec24ea2ca186",
                                    "label": "MLE_HASH",
                                    "info": {
                                        "ComponentName": "MLE_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        },
                        "pcr_18": {
                            "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
                            "event": [
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
                                    "label": "SINIT_PUBKEY_HASH",
                                    "info": {
                                        "ComponentName": "SINIT_PUBKEY_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
                                    "label": "CPU_SCRTM_STAT",
                                    "info": {
                                        "ComponentName": "CPU_SCRTM_STAT",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
                                    "label": "OSSINITDATA_CAP_HASH",
                                    "info": {
                                        "ComponentName": "OSSINITDATA_CAP_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                                    "label": "LCP_AUTHORITIES_HASH",
                                    "info": {
                                        "ComponentName": "LCP_AUTHORITIES_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
                                    "label": "NV_INFO_HASH",
                                    "info": {
                                        "ComponentName": "NV_INFO_HASH",
                                        "EventName": "OpenSource.EventName"
                                    }
                                },
                                {
                                    "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                                    "value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
                                    "label": "tb_policy",
                                    "info": {
                                        "ComponentName": "tb_policy",
                                        "EventName": "OpenSource.EventName"
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "signature": "EyuFK0QurCblcI8uRjzpn21gxvBdR99qtLDC1MEVuZ0bqLG4GC9qz27IjBO3Laniuu6e8RaVTkl6T2abnv3N+93VpSYHPKxM/ly7pM16fZmnIq1vQf0cC84tP4udL32mkq2l7riYxl8TupVrjMH9cc39Nd5JW8aRfLMcqqG6V3AHJD4mFdi0FAGDRMIlVq7WMjkZbZ8scVMH0ytJymRAq53Z8/ontdcWbXy3i1Lwrh9yrQufQ67g05UDjQJQTv+YXW9s0wR55O1I+RaZaxb3+lsBbtt7O21oT1+9CwIHN6gPP9L8OP3UDRPFN3mUA8rSHu3btnH1K1gEO1Dz+TnXIZ9puattdvOUTLjIIOMJcH/Y4ED0R3Bhln0PpRPxcgaD/Ku2dZxZWdhYHAkvIA5d8HquuAw6SkVoA5CH8DUkihSrbdQszbfpXWhFiTamfj7wpQLcacNsXES9IWvHD14GytBBfZ5lJhZ2I7OLF9QSivZh9P489upgH8rdV3qxY1jj"
        }`

// Delete Flavor
func (store *MockFlavorStore) Delete(id uuid.UUID) error {
	for i, f := range store.flavorStore {
		if f.Flavor.Meta.ID == id {
			store.flavorStore[i] = hvs.SignedFlavor{}
			return nil
		}
	}
	return errors.New(commErr.RowsNotFound)
}

// Retrieve returns Flavor
func (store *MockFlavorStore) Retrieve(id uuid.UUID) (*hvs.SignedFlavor, error) {
	for _, f := range store.flavorStore {
		if f.Flavor.Meta.ID == id {
			return &f, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Search returns a filtered list of flavors per the provided FlavorFilterCriteria
func (store *MockFlavorStore) Search(criteria *models.FlavorVerificationFC) ([]hvs.SignedFlavor, error) {
	var sfs []hvs.SignedFlavor
	// flavor filter empty
	if criteria == nil {
		return store.flavorStore, nil
	}

	// return all entries
	if reflect.DeepEqual(*criteria, models.FlavorFilterCriteria{}) {
		return store.flavorStore, nil
	}

	var sfFiltered []hvs.SignedFlavor
	// Flavor ID filter
	if len(criteria.FlavorFC.Ids) > 0 {
		for _, f := range store.flavorStore {
			for _, id := range criteria.FlavorFC.Ids {
				if f.Flavor.Meta.ID == id {
					sfFiltered = append(sfFiltered, f)
					break
				}
			}
		}
		sfs = sfFiltered
	} else if criteria.FlavorFC.FlavorgroupID != uuid.Nil ||
		len(criteria.FlavorFC.FlavorParts) >= 1 || len(criteria.FlavorPartsWithLatest) >= 1 {
		flavorPartsWithLatestMap := getFlavorPartsWithLatestMap(criteria.FlavorFC.FlavorParts, criteria.FlavorPartsWithLatest)
		// Find flavors for given flavor group Id
		var fIds = store.FlavorFlavorGroupStore[criteria.FlavorFC.FlavorgroupID]

		// for each flavors check the flavor part in flavorPartsWithLatestMap is present
		for _, fId := range fIds {
			f, _ := store.Retrieve(fId)
			if f != nil {
				var flvrPart cf.FlavorPart
				err := (&flvrPart).Parse(f.Flavor.Meta.Description.FlavorPart)
				if err != nil {
					defaultLog.WithError(err).Errorf("Error parsing Flavor part")
				}
				if f, _ := store.Retrieve(fId); flavorPartsWithLatestMap[flvrPart] == true {
					sfs = append(sfs, *f)
				}
			}
		}
	}
	return sfs, nil
}

// Create inserts a Flavor
func (store *MockFlavorStore) Create(sf *hvs.SignedFlavor) (*hvs.SignedFlavor, error) {
	//It is not right way to directly append the pointer, reference will be copied. Copy only the values.
	rec := hvs.SignedFlavor{
		Flavor:    sf.Flavor,
		Signature: sf.Signature,
	}
	store.flavorStore = append(store.flavorStore, rec)
	return sf, nil
}


// NewMockFlavorStore provides one dummy data for Flavors
func NewMockFlavorStore() *MockFlavorStore {
	store := &MockFlavorStore{}

	var sf hvs.SignedFlavor
	err := json.Unmarshal([]byte(flavor), &sf)
	fmt.Println("error: ", err)

	// add to store
	_, err = store.Create(&sf)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}
	return store
}

func NewFakeFlavorStoreWithAllFlavors(flavorFilePath string) *MockFlavorStore {
	store := &MockFlavorStore{}
	var signedFlavors []hvs.SignedFlavor

	flavorsJSON, _ := ioutil.ReadFile(flavorFilePath)

	err := json.Unmarshal(flavorsJSON, &signedFlavors)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error unmarshalling flavor")
	}
	for _, flvr := range signedFlavors {
		_, err = store.Create(&flvr)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating Flavor")
		}
	}
	return store
}

func getFlavorPartsWithLatestMap(flavorParts []cf.FlavorPart, flavorPartsWithLatestMap map[cf.FlavorPart]bool) map[cf.FlavorPart]bool {
	if len(flavorParts) <= 0 {
		return flavorPartsWithLatestMap
	}
	if len(flavorPartsWithLatestMap) <= 0 {
		flavorPartsWithLatestMap = make(map[cf.FlavorPart]bool)
	}
	for _, flavorPart := range flavorParts {
		if _, ok := flavorPartsWithLatestMap[flavorPart]; !ok {
			flavorPartsWithLatestMap[flavorPart] = false
		}
	}

	return flavorPartsWithLatestMap
}
