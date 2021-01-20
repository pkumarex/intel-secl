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

	//linux
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

	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, testHostManifestPcrEventLogEntry)

	rule, err := NewPcrEventLogEquals(nil, &testHostManifestPcrEventLogEntry, uuid.New(), common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals rule verified for Intel Host Trust Policy")

	//vmware
	vmHostManifest := types.HostManifest{
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

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testHostManifestEventLogEntry)

	rule, err = NewPcrEventLogEquals(&testHostManifestEventLogEntry, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals rule verified for VMware Host Trust Policy")

}

// Provide the 'testExpectedEventLogEntry' to the rule (it just contains to events)
// and a host manifest event log ('') that has component names that the excluding rule
// should ignore.
func TestPcrEventLogEqualsExcludingNoFault(t *testing.T) {

	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

	//linux
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

	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, testExpectedPcrEventLogEntry)

	rule, err := NewPcrEventLogEqualsExcluding(nil, &testExpectedPcrEventLogEntry, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals Excluding rule verified for Intel Host Trust Policy")

	//vmware
	vmHostManifest := types.HostManifest{
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
	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedEventLogEntry)

	rule, err = NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, nil, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals Excluding rule verified for VMware Host Trust Policy")
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingFault(t *testing.T) {

	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

	//linux
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

	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, hostEventsLog)

	rule, err := NewPcrEventLogEqualsExcluding(nil, &flavorEventsLog, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware

	vmHostManifest := types.HostManifest{
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

	flavorEvents := types.EventLogEntry{
		PcrIndex: types.PCR0,
		PcrBank:  types.SHA256,
		EventLogs: []types.EventLog{
			{
				Value: zeros,
			},
		},
	}

	// Put something in PCR1 (not PCR0) to invoke PcrMissingEventLog fault
	hostEvents := types.EventLogEntry{
		PcrIndex: types.PCR1,
		PcrBank:  types.SHA256,
		EventLogs: []types.EventLog{
			{
				Value: ones,
			},
		},
	}

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEvents)

	rule, err = NewPcrEventLogEqualsExcluding(&flavorEvents, nil, nil, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)

}

// create a copy of 'testExpectedEventLogEntries' and add new eventlog in the
// host manifest so that a PcrEventLogContainsUnexpectedEntries fault is raised.
func TestPcrEventLogEqualsExcludingPcrEventLogContainsUnexpectedEntriesFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

	//linux
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

	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, unexpectedPcrEventLogs)

	rule, err := NewPcrEventLogEqualsExcluding(nil, &testExpectedPcrEventLogEntry, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogContainsUnexpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].UnexpectedEntriesNew)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	vmHostManifest := types.HostManifest{
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
	unexpectedEventLogs := types.EventLogEntry{
		PcrIndex: testHostManifestEventLogEntry.PcrIndex,
		PcrBank:  testHostManifestEventLogEntry.PcrBank,
	}
	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, testHostManifestEventLogEntry.EventLogs...)
	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, types.EventLog{
		Value: "x",
	})

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	rule, err = NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, nil, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogContainsUnexpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].UnexpectedEntries)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)

}

// create a copy of 'testExpectedEventLogEntries' and remove an eventlog in the
// host manifest so that a PcrEventLogMissingExpectedEntries fault is raised.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingExpectedEntriesFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

	//linux
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

	hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMapNew.Sha256EventLogs, unexpectedPcrEventLogs)

	rule, err := NewPcrEventLogEqualsExcluding(nil, &testExpectedPcrEventLogEntry, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntriesNew)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[0].Description)

	//vmware
	vmHostManifest := types.HostManifest{
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
	unexpectedEventLogs := types.EventLogEntry{
		PcrIndex: testHostManifestEventLogEntry.PcrIndex,
		PcrBank:  testHostManifestEventLogEntry.PcrBank,
	}

	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, testHostManifestEventLogEntry.EventLogs[1:]...)

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	rule, err = NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, nil, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)
}
