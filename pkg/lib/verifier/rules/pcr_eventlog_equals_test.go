/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Provide the same event logs in the manifest and to the PcrEventLogEquals rule, expecting
// no faults.
func TestPcrEventLogEqualsNoFault(t *testing.T) {

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testHostManifestEventLogEntry)

	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	rule, err := NewPcrEventLogEquals(&testHostManifestEventLogEntry, newUuid, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
}

// Provide the 'testExpectedEventLogEntry' to the rule (it just contains to events)
// and a host manifest event log ('') that has component names that the excluding rule
// should ignore.
func TestPcrEventLogEqualsExcludingNoFault(t *testing.T) {

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testHostManifestEventLogEntry)

	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, newUuid, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingFault(t *testing.T) {

	flavorEvents := types.EventLogEntry{
		PcrIndex: types.PCR0,
		PcrBank:  types.SHA256,
		EventLogs: []types.EventLog{
			{
				DigestType: util.EVENT_LOG_DIGEST_SHA256,
				Value:      zeros,
			},
		},
	}

	// Put something in PCR1 (not PCR0) to invoke PcrMissingEventLog fault
	hostEvents := types.EventLogEntry{
		PcrIndex: types.PCR1,
		PcrBank:  types.SHA256,
		EventLogs: []types.EventLog{
			{
				DigestType: util.EVENT_LOG_DIGEST_SHA256,
				Value:      ones,
			},
		},
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEvents)

	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	rule, err := NewPcrEventLogEqualsExcluding(&flavorEvents, nil, newUuid, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// create a copy of 'testExpectedEventLogEntries' and add new eventlog in the
// host manifest so that a PcrEventLogContainsUnexpectedEntries fault is raised.
func TestPcrEventLogEqualsExcludingPcrEventLogContainsUnexpectedEntriesFault(t *testing.T) {
	unexpectedEventLogs := types.EventLogEntry{
		PcrIndex: testHostManifestEventLogEntry.PcrIndex,
		PcrBank:  testHostManifestEventLogEntry.PcrBank,
	}

	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, testHostManifestEventLogEntry.EventLogs...)
	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, types.EventLog{
		DigestType: util.EVENT_LOG_DIGEST_SHA256,
		Value:      "x",
	})

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, newUuid, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogContainsUnexpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].UnexpectedEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// create a copy of 'testExpectedEventLogEntries' and remove an eventlog in the
// host manifest so that a PcrEventLogMissingExpectedEntries fault is raised.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingExpectedEntriesFault(t *testing.T) {
	unexpectedEventLogs := types.EventLogEntry{
		PcrIndex: testHostManifestEventLogEntry.PcrIndex,
		PcrBank:  testHostManifestEventLogEntry.PcrBank,
	}

	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, testHostManifestEventLogEntry.EventLogs[1:]...)

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, newUuid, common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
