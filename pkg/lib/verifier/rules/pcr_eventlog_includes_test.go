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

// Create an event log that is used by the hostManifest and the rule,
// expecting that they match and will not generate any faults.
func TestPcrEventLogIncludesNoFault(t *testing.T) {
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)
	rule, err := NewPcrEventLogIncludes(&testExpectedPcrEventLogEntry, common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Includes rule verified")
}

// Create an event log for the rule with two measurements and only provide
// one to the host manifest.  Expect a 'FaultPcrEventlogMissingExpectedEntries'
// fault.
func TestPcrEventLogIncludesMissingMeasurement(t *testing.T) {
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	flavorEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	assert.Equal(t, 1, len(result.Faults[0].MissingEntries))
	assert.Equal(t, ones, result.Faults[0].MissingEntries[0].Measurement)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Create flavor/host events that use the same bank/index but
// different measurement to nvoke the 'PcrEventlogMissingExpectedEntries'
// fault.
func TestPcrEventLogIncludesDifferentMeasurement(t *testing.T) {
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	flavorEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	// host manifest has 'ones' for the measurement (not 'zeros')
	hostEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	assert.Equal(t, 1, len(result.Faults[0].MissingEntries))
	assert.Equal(t, zeros, result.Faults[0].MissingEntries[0].Measurement)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogIncludesPcrEventLogMissingFault(t *testing.T) {
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	flavorEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	// Put something in PCR1 (not PCR0) to invoke PcrMissingEventLog fault
	hostEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 1,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Create a host event log that wihtout an event log to invoke a
// 'PcrEventLogMissing' fault.
func TestPcrEventLogIncludesNoEventLogInHostManifest(t *testing.T) {
	// Create a HostManifest without any event logs to invoke PcrEventLogMissing fault.
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs: []types.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: types.SHA256,
				},
			},
		},
	}

	flavorEventsLog := types.TpmEventLog{
		Pcr: types.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []types.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, common.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
