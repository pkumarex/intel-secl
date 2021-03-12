/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"testing"

	"github.com/google/uuid"
	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	"github.com/stretchr/testify/assert"
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testHostManifestPcrEventLogEntry)
	rule, err := NewPcrEventLogEquals(&testHostManifestPcrEventLogEntry, uuid.New(), common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals rule verified")
}

// Provide the 'testExpectedPcrEventLogEntry' to the rule (it just contains to events)
// and a host manifest event log ('') that has component names that the excluding rule
// should ignore.
func TestPcrEventLogEqualsExcludingNoFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, excludetag, uuid.New(), common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals Excluding rule verified")
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	flavorEventsLog := types.TpmEventLog{
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

	// Put something in PCR1 (not PCR0) to invoke PcrMissingEventLog fault
	hostEventsLog := types.TpmEventLog{
		Pcr: types.PCR{
			Index: 1,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLogCriteria{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogEqualsExcluding(&flavorEventsLog, excludetag, uuid.New(), common.FlavorPartPlatform)
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
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	unexpectedPcrEventLogs := types.TpmEventLog{
		Pcr: types.PCR{
			Index: testHostManifestPcrEventLogEntry.Pcr.Index,
			Bank:  testHostManifestPcrEventLogEntry.Pcr.Bank,
		},
	}
	unexpectedPcrEventLogs.TpmEvent = append(unexpectedPcrEventLogs.TpmEvent, testHostManifestPcrEventLogEntry.TpmEvent...)
	unexpectedPcrEventLogs.TpmEvent = append(unexpectedPcrEventLogs.TpmEvent, types.EventLogCriteria{
		TypeName:    util.EVENT_LOG_DIGEST_SHA256,
		Measurement: "x",
	})

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedPcrEventLogs)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, excludetag, uuid.New(), common.FlavorPartPlatform)
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
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	unexpectedPcrEventLogs := types.TpmEventLog{
		Pcr: types.PCR{
			Index: testHostManifestPcrEventLogEntry.Pcr.Index,
			Bank:  testHostManifestPcrEventLogEntry.Pcr.Bank,
		},
	}

	unexpectedPcrEventLogs.TpmEvent = append(unexpectedPcrEventLogs.TpmEvent, testHostManifestPcrEventLogEntry.TpmEvent[1:]...)
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedPcrEventLogs)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, excludetag, uuid.New(), common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
