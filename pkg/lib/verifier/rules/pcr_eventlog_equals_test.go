/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testHostManifestPcrEventLogEntry)

	rule, err := NewPcrEventLogEquals(&testHostManifestPcrEventLogEntry, uuid.New(), common.FlavorPartPlatform)

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

	rule, err = NewPcrEventLogEquals(&testHostManifestEventLogEntry, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	fmt.Println("fault length:", len(result.Faults))
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals rule verified for VMware Host Trust Policy")

}

// Provide the 'testExpectedEventLogEntry' to the rule (it just contains to events)
// and a host manifest event log ('') that has component names that the excluding rule
// should ignore.
func TestPcrEventLogEqualsExcludingNoFault(t *testing.T) {

	var excludetag = []string{"commandline.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)

	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

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

	rule, err = NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals Excluding rule verified for VMware Host Trust Policy")
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingFault(t *testing.T) {

	var excludetag = []string{"commandline.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	flavorEventsLog := types.EventLogEntry{

		PcrIndex: 0,
		PcrBank:  types.SHA256,

		PcrEventLogs: []types.EventLogCriteria{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	// Put something in PCR1 (not PCR0) to invoke PcrMissingEventLog fault
	hostEventsLog := types.EventLogEntry{
		PcrIndex: 1,
		PcrBank:  types.SHA256,

		PcrEventLogs: []types.EventLogCriteria{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)

	rule, err := NewPcrEventLogEqualsExcluding(&flavorEventsLog, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

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

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEvents)

	rule, err = NewPcrEventLogEqualsExcluding(&flavorEvents, nil, nil, uuid.New(), common.FlavorPartPlatform)

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
	var excludetag = []string{"commandline.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	unexpectedEventLogs := types.EventLogEntry{
		PcrIndex:  testHostManifestPcrEventLogEntry.PcrIndex,
		PcrBank:   testHostManifestPcrEventLogEntry.PcrBank,
		EventLogs: []types.EventLog{},
	}
	unexpectedEventLogs.PcrEventLogs = append(unexpectedEventLogs.PcrEventLogs, testHostManifestPcrEventLogEntry.PcrEventLogs...)
	unexpectedEventLogs.PcrEventLogs = append(unexpectedEventLogs.PcrEventLogs, types.EventLogCriteria{
		TypeName:    util.EVENT_LOG_DIGEST_SHA256,
		Measurement: "x",
	})

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

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
	unexpectedEventLogs = types.EventLogEntry{
		PcrIndex:     testHostManifestEventLogEntry.PcrIndex,
		PcrBank:      testHostManifestEventLogEntry.PcrBank,
		PcrEventLogs: []types.EventLogCriteria{},
	}
	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, testHostManifestEventLogEntry.EventLogs...)
	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, types.EventLog{
		DigestType: util.EVENT_LOG_DIGEST_SHA256,
		Value:      "x",
	})

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	rule, err = NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, nil, uuid.New(), common.FlavorPartPlatform)

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
	var excludetag = []string{"commandline.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	unexpectedEventLogs := types.EventLogEntry{
		PcrIndex:  testHostManifestPcrEventLogEntry.PcrIndex,
		PcrBank:   testHostManifestPcrEventLogEntry.PcrBank,
		EventLogs: []types.EventLog{},
	}

	unexpectedEventLogs.PcrEventLogs = append(unexpectedEventLogs.PcrEventLogs, testHostManifestPcrEventLogEntry.PcrEventLogs[1:]...)

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, nil, excludetag, uuid.New(), common.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 2, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[1].Name)
	assert.NotNil(t, result.Faults[1].MissingEntriesNew)
	t.Logf("Intel Host Trust Policy - Fault description: %s", result.Faults[1].Description)

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
	unexpectedEventLogs = types.EventLogEntry{
		PcrIndex:     testHostManifestEventLogEntry.PcrIndex,
		PcrBank:      testHostManifestEventLogEntry.PcrBank,
		PcrEventLogs: []types.EventLogCriteria{},
	}

	unexpectedEventLogs.EventLogs = append(unexpectedEventLogs.EventLogs, testHostManifestEventLogEntry.EventLogs[1:]...)

	vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(vmHostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedEventLogs)

	rule, err = NewPcrEventLogEqualsExcluding(&testExpectedEventLogEntry, nil, nil, uuid.New(), common.FlavorPartPlatform)

	result, err = rule.Apply(&vmHostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	t.Logf("VMware Host Trust Policy - Fault description: %s", result.Faults[0].Description)
}
