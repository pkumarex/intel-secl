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
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	"github.com/stretchr/testify/assert"
)

func TestPcrEventLogIntegrityNoFault(t *testing.T) {

	//linux
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: expectedCumulativeHash,
	}

	expectedPcrLog1 := types.Pcr{

		Index:   0,
		PcrBank: "SHA256",
		Value:   expectedCumulativeHash,
	}

	hostManifest := types.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, testExpectedPcrEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcrLog1)

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, nil, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Integrity rule verified for Intel Host Trust Policy")

	//vmware
	expectedCumulativeHash, err = testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

	hostManifest = types.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcr)

	rule, err = NewPcrEventLogIntegrity(nil, &expectedPcr, common.FlavorPartPlatform)

	result, err = rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Integrity rule verified for VMware Host Trust Policy")

}

func TestPcrEventLogIntegrityPcrValueMissingFault(t *testing.T) {

	//linux
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

	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: expectedCumulativeHash,
	}

	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, testExpectedPcrEventLogEntry)

	// if the pcr is no incuded, the PcrEventLogIntegrity rule should return
	// a PcrMissingFault
	// hostManifest.PcrManifest.Sha256Pcrs = ...not set

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, nil, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrValueMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	vmHostManifest := types.HostManifest{
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

	expectedCumulativeHash, err = testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedEventLogEntry)

	// if the pcr is no incuded, the PcrEventLogIntegrity rule should return
	// a PcrMissingFault
	// vmHostManifest.PcrManifest.Sha256Pcrs = ...not set

	rule, err = NewPcrEventLogIntegrity(nil, &expectedPcr, common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrValueMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)

}

func TestPcrEventLogIntegrityPcrEventLogMissingFault(t *testing.T) {

	//linux
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog1 := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}
	expectedPcrLog := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: expectedCumulativeHash,
	}

	hostManifest := types.HostManifest{}
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcrLog1)
	// omit the event log from the host manifest to invoke "PcrEventLogMissing" fault...
	//hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, eventLogEntry)

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, nil, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	expectedCumulativeHash, err = testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

	hostManifest = types.HostManifest{}
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcr)
	// omit the event log from the host manifest to invoke "PcrEventLogMissing" fault...
	//hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, eventLogEntry)

	rule, err = NewPcrEventLogIntegrity(nil, &expectedPcr, common.FlavorPartPlatform)

	result, err = rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)
}

func TestPcrEventLogIntegrityPcrEventLogInvalidFault(t *testing.T) {

	//linux
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := types.PCRS{
		PCR: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: expectedCumulativeHash,
	}

	invalidPcrEventLogEntry := types.TpmEventLog{
		Pcr: types.PCR{
			Index: 0,
			Bank:  "SHA256",
		},

		TpmEvent: []types.EventLogCriteria{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	invalidCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	invalidPcrLog := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   invalidCumulativeHash,
	}

	hostManifest := types.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, invalidPcrEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, invalidPcrLog)

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, nil, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogInvalid, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware

	expectedCumulativeHash, err = testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

	invalidEventLogEntry := types.EventLogEntry{
		PcrIndex: types.PCR0,
		PcrBank:  types.SHA256,
		EventLogs: []types.EventLog{
			{
				Value: zeros,
			},
		},
	}

	invalidCumulativeHash, err = testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	invalidPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   invalidCumulativeHash,
	}

	hostManifest = types.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, invalidEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, invalidPcr)

	rule, err = NewPcrEventLogIntegrity(nil, &expectedPcr, common.FlavorPartPlatform)

	result, err = rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogInvalid, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)
}
