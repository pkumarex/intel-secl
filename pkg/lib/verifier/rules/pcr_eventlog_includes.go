/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

//NewPcrEventLogIncludes creates the rule that will check
//if all the actual event log measurements included in expected
func NewPcrEventLogIncludes(expectedEventLogEntry *types.EventLogEntry, expectedPcrEventLogEntry *types.TpmEventLog, expectedPcr *types.Pcr, marker common.FlavorPart) (Rule, error) {

	var rule pcrEventLogIncludes

	if expectedPcrEventLogEntry != nil {
		rule = pcrEventLogIncludes{
			expectedPcrEventLogEntry: expectedPcrEventLogEntry,
			marker:                   marker,
		}
	} else if expectedEventLogEntry != nil {
		rule = pcrEventLogIncludes{
			expectedEventLogEntry: expectedEventLogEntry,
			expectedPcr:           expectedPcr,
			marker:                marker,
		}
	} else {
		return nil, errors.New("The expected event log cannot be nil")
	}
	return &rule, nil
}

type pcrEventLogIncludes struct {
	expectedEventLogEntry    *types.EventLogEntry
	expectedPcrEventLogEntry *types.TpmEventLog
	expectedPcr              *types.Pcr
	marker                   common.FlavorPart
}

// - If the PcrManifest is not present in the host manifest, raise PcrManifestMissing fault.
// - if the host manifest does not have any log entries, or it doesn't have any value
//   at the bank/index 'expected', raise "PcrEventLogMissing".
// - if the log at bank/index does not have the same events as 'expected', raise
//   "PcrEventLogMissingExpectedEntries".
func (rule *pcrEventLogIncludes) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RulePcrEventLogIncludes

	if rule.expectedPcrEventLogEntry != nil {
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)
		result.Rule.ExpectedPcrEventLogEntry = rule.expectedPcrEventLogEntry

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMapNew.GetEventLogNew(rule.expectedPcrEventLogEntry.Pcr.Bank, rule.expectedPcrEventLogEntry.Pcr.Index)
			if err != nil {
				return nil, errors.Wrap(err, "Error in retrieving the actual event log values in pcr event log includes rule")
			}

			if actualEventLogCriteria == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index), types.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)))
			} else {
				actualEventLog := &types.TpmEventLog{}
				actualEventLog.TpmEvent = actualEventLogCriteria
				actualEventLog.Pcr.Index = pIndex
				actualEventLog.Pcr.Bank = bank

				// subtract the 'actual' event log measurements from 'expected'.
				// if there are any left in 'expected', then 'actual' did not include all entries

				missingEvents, missingAttr, err := rule.expectedPcrEventLogEntry.Subtract(actualEventLog)

				if err != nil {
					return nil, errors.Wrap(err, "Error subtracting actual from expected event logs in pcr eventlog includes rule.")
				}

				if len(missingEvents.TpmEvent) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(nil, missingEvents))
				}

				if len(missingAttr.TpmEvent) > 0 {
					index := types.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index)
					bank := types.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)

					mismatchInfo := hvs.MismatchField{

						Name:           constants.PcrEventLogMissingFields,
						Description:    fmt.Sprintf("Module manifest for PCR %d of %s value contains %d missing entries", rule.expectedPcrEventLogEntry.Pcr.Index, rule.expectedPcrEventLogEntry.Pcr.Bank, len(missingAttr.TpmEvent)),
						PcrIndex:       &index,
						PcrBank:        &bank,
						MissingEntries: missingAttr.TpmEvent,
					}
					result.MismatchField = append(result.MismatchField, mismatchInfo)
				}
			}
		}
	} else {
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)
		result.Rule.ExpectedEventLogs = rule.expectedEventLogEntry.EventLogs
		result.Rule.ExpectedPcr = rule.expectedPcr

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {
			actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
			if err != nil {
				return nil, errors.Wrap(err, "Error in retrieving the actual event log values in pcr event log includes rule")
			}

			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(rule.expectedEventLogEntry.PcrIndex, rule.expectedEventLogEntry.PcrBank))
			} else {
				// subtract the 'actual' event log measurements from 'expected'.
				// if there are any left in 'expected', then 'actual' did not include all entries

				missingEvents, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
				if err != nil {
					return nil, errors.Wrap(err, "Error subtracting actual from expected event logs in pcr eventlog includes rule.")
				}

				if len(missingEvents.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEvents, nil))
				}
			}
		}

	}

	return &result, nil
}
