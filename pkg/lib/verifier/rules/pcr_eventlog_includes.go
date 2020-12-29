/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"
	"reflect"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

func NewPcrEventLogIncludes(expectedEventLogEntry *types.EventLogEntry, expectedPcr *types.Pcr, marker common.FlavorPart) (Rule, error) {

	var rule pcrEventLogIncludes

	if !reflect.DeepEqual(expectedEventLogEntry.PcrEventLogs, []types.EventLogCriteria{}) {
		rule = pcrEventLogIncludes{
			expectedEventLogEntry: expectedEventLogEntry,
			marker:                marker,
		}
	} else if !reflect.DeepEqual(expectedEventLogEntry.EventLogs, []types.EventLog{}) {
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
	expectedEventLogEntry *types.EventLogEntry
	expectedPcr           *types.Pcr
	marker                common.FlavorPart
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

	if !reflect.DeepEqual(rule.expectedEventLogEntry.PcrEventLogs, []types.EventLogCriteria{}) {
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)
		result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
			if err != nil {
				return nil, err
			}

			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedEventLogEntry.PcrIndex), rule.expectedEventLogEntry.PcrBank))
			} else {

				// subtract the 'actual' event log measurements from 'expected'.
				// if there are any left in 'expected', then 'actual' did not include all entries

				missingEvents, missingAttr, err := rule.expectedEventLogEntry.Subtract(actualEventLog)

				if err != nil {
					return nil, errors.Wrap(err, "Error subtracting event logs in pcr eventlog includes rule.")
				}

				if len(missingEvents.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEvents))
				}

				if len(missingAttr.EventLogs) > 0 {
					Pi := types.PcrIndex(rule.expectedEventLogEntry.PcrIndex)

					mismatchInfo := hvs.MismatchField{

						Name:           constants.PcrEventLogMissingFields,
						Description:    fmt.Sprintf("Module manifest for PCR %d of %s value contains %d missing entries", rule.expectedEventLogEntry.PcrIndex, rule.expectedEventLogEntry.PcrBank, len(missingAttr.PcrEventLogs)),
						PcrIndex:       &Pi,
						PcrBank:        &rule.expectedEventLogEntry.PcrBank,
						MissingEntries: missingAttr.EventLogs,
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
				return nil, err
			}

			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(rule.expectedEventLogEntry.PcrIndex, rule.expectedEventLogEntry.PcrBank))
			} else {
				// subtract the 'actual' event log measurements from 'expected'.
				// if there are any left in 'expected', then 'actual' did not include all entries

				missingEvents, _, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
				if err != nil {
					return nil, errors.Wrap(err, "Error subtracting event logs in pcr eventlog includes rule.")
				}

				if len(missingEvents.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEvents))
				}
			}
		}

	}

	return &result, nil
}
