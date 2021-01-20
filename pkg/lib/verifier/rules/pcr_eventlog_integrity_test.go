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

func TestPcrEventLogIntegrityNoFault(t *testing.T) {

	expectedCumulativeHash, err := testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

	hostManifest := types.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcr)

	rule, err := NewPcrEventLogIntegrity(&expectedPcr, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
}

func TestPcrEventLogIntegrityPcrValueMissingFault(t *testing.T) {

	expectedCumulativeHash, err := testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedEventLogEntry)

	// if the pcr is no incuded, the PcrEventLogIntegrity rule should return
	// a PcrMissingFault
	// hostManifest.PcrManifest.Sha256Pcrs = ...not set

	rule, err := NewPcrEventLogIntegrity(&expectedPcr, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrValueMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestPcrEventLogIntegrityPcrEventLogMissingFault(t *testing.T) {

	expectedCumulativeHash, err := testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   expectedCumulativeHash,
	}

	hostManifest := types.HostManifest{}
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcr)
	// omit the event log from the host manifest to invoke "PcrEventLogMissing" fault...
	//hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, eventLogEntry)

	rule, err := NewPcrEventLogIntegrity(&expectedPcr, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestPcrEventLogIntegrityPcrEventLogInvalidFault(t *testing.T) {

	expectedCumulativeHash, err := testExpectedEventLogEntry.Replay()
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

	invalidCumulativeHash, err := testExpectedEventLogEntry.Replay()
	assert.NoError(t, err)

	invalidPcr := types.Pcr{
		Index:   types.PCR0,
		PcrBank: types.SHA256,
		Value:   invalidCumulativeHash,
	}

	hostManifest := types.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, invalidEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, invalidPcr)

	rule, err := NewPcrEventLogIntegrity(&expectedPcr, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogInvalid, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, types.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
