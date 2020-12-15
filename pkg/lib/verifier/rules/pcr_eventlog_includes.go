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

func NewPcrEventLogIncludes(expectedEventLogEntry *types.NewFVEventLogEntry, marker common.FlavorPart) (Rule, error) {
	if expectedEventLogEntry == nil {
		return nil, errors.New("The expected event log cannot be nil")
	}

	rule := pcrEventLogIncludes{
		expectedEventLogEntry: expectedEventLogEntry,
		marker:                marker,
	}
	return &rule, nil
}

type pcrEventLogIncludes struct {
	expectedEventLogEntry *types.NewFVEventLogEntry
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
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)
	result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {

		actualEventLog, err := hostManifest.PcrManifest.NewFVPcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.NewPCR.PcrBank, rule.expectedEventLogEntry.NewPCR.PcrIndex)
		if err != nil {
			return nil, err
		}

		if actualEventLog == nil {
			result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedEventLogEntry.NewPCR.PcrIndex), rule.expectedEventLogEntry.NewPCR.PcrBank))
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
				Pi := types.PcrIndex(rule.expectedEventLogEntry.NewPCR.PcrIndex)

				mismatchInfo := hvs.MismatchField{

					Name:           constants.PcrEventLogMissingFields,
					Description:    fmt.Sprintf("Module manifest for PCR %d of %s value contains %d missing entries", rule.expectedEventLogEntry.NewPCR.PcrIndex, rule.expectedEventLogEntry.NewPCR.PcrBank, len(missingAttr.EventLogs)),
					PcrIndex:       &Pi,
					PcrBank:        &rule.expectedEventLogEntry.NewPCR.PcrBank,
					MissingEntries: missingAttr.EventLogs,
				}
				result.MismatchField = append(result.MismatchField, mismatchInfo)
			}
		}
	}

	return &result, nil
}
