/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"testing"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/stretchr/testify/assert"
)

func TestPcrMatchesConstantNoFault(t *testing.T) {

	expectedPcr := types.Pcr{
		Index:   0,
		Value:   PCR_VALID_256,
		PcrBank: types.SHA256,
	}

	expectedPcrLogs := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: PCR_VALID_256,
	}

	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.Pcr{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	//linux
	rule, err := NewPcrMatchesConstant(nil, &expectedPcrLogs, common.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
	assert.True(t, result.Trusted)
	t.Logf("Pcr matches constant rule verified for Intel Host Trust Policy")

	//vmware
	rule, err = NewPcrMatchesConstant(&expectedPcr, nil, common.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err = rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
	assert.True(t, result.Trusted)
	t.Logf("Pcr matches constant rule verified for VMware Host Trust Policy")
}

func TestPcrMatchesConstantPcrManifestMissingFault(t *testing.T) {

	expectedPcrLogs := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: PCR_VALID_256,
	}

	expectedPcr := types.Pcr{
		Index:   0,
		Value:   PCR_VALID_256,
		PcrBank: types.SHA256,
	}
	//linux
	rule, err := NewPcrMatchesConstant(nil, &expectedPcrLogs, common.FlavorPartPlatform)
	assert.NoError(t, err)

	// provide a manifest without a PcrManifest and expect FaultPcrManifestMissing
	result, err := rule.Apply(&types.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrManifestMissing)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	rule, err = NewPcrMatchesConstant(&expectedPcr, nil, common.FlavorPartPlatform)
	assert.NoError(t, err)

	// provide a manifest without a PcrManifest and expect FaultPcrManifestMissing
	result, err = rule.Apply(&types.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrManifestMissing)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)

}

func TestPcrMatchesConstantMismatchFault(t *testing.T) {

	expectedPcrLogs := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: PCR_VALID_256,
	}

	expectedPcr := types.Pcr{
		Index:   0,
		Value:   PCR_VALID_256,
		PcrBank: types.SHA256,
	}

	// host manifest with 'invalid' value for pcr0
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.Pcr{
				{
					Index:   0,
					Value:   PCR_INVALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	//linux
	rule, err := NewPcrMatchesConstant(nil, &expectedPcrLogs, common.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMismatchSHA256)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	rule, err = NewPcrMatchesConstant(&expectedPcr, nil, common.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err = rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMismatchSHA256)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)
}

func TestPcrMatchesConstantMissingFault(t *testing.T) {

	// empty manifest will result in 'missing' fault
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.Pcr{
				{
					Index:   1,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	expectedPcrLogs := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: PCR_VALID_256,
	}

	expectedPcr := types.Pcr{
		Index:   0,
		Value:   PCR_VALID_256,
		PcrBank: types.SHA256,
	}

	//linux
	rule, err := NewPcrMatchesConstant(nil, &expectedPcrLogs, common.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMissing)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	rule, err = NewPcrMatchesConstant(&expectedPcr, nil, common.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err = rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMissing)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)
}
