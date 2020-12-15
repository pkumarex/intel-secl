/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"

	"github.com/google/uuid"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

//
func NewPcrEventLogEquals(expectedEventLogEntry *types.NewFVEventLogEntry, marker common.FlavorPart) (Rule, error) {

	// create the rule without the defaultExcludeComponents/labels so that all
	// events are evaluated (i.e. no 'excludes').
	rule := pcrEventLogEquals{
		expectedEventLogEntry: expectedEventLogEntry,
		ruleName:              constants.RulePcrEventLogEquals,
		marker:                marker,
	}

	return &rule, nil
}

//This rule implements both PcrEventLogEquals and PcrEventLogEqualsExcluding.  Only
// the 'new' functions are different, populating the rule name and 'excludes'.
func NewPcrEventLogEqualsExcluding(expectedEventLogEntry *types.NewFVEventLogEntry, expectedPcr *model.NewFVPcrEx, excludedEvents []string, marker common.FlavorPart) (Rule, error) {

	// create the rule providing the defaultExcludeComponents and labels so
	// they are not included for evaluation during 'Apply'.
	rule := pcrEventLogEquals{
		expectedEventLogEntry: expectedEventLogEntry,
		expectedPcr:           expectedPcr,
		excludeTags:           excludedEvents,
		marker:                marker,
		ruleName:              constants.RulePcrEventLogEqualsExcluding,
	}

	return &rule, nil
}

type pcrEventLogEquals struct {
	expectedEventLogEntry *types.NewFVEventLogEntry
	expectedPcr           *model.NewFVPcrEx
	flavorID              *uuid.UUID
	marker                common.FlavorPart
	ruleName              string
	excludeTags           []string
}

// - If the PcrManifest is not present in the host manifest, raise PcrManifestMissing fault.
// - If the PcrManifest's event log is not present in the host manifest, raise PcrEventLogMissing fault.
// - Otherwise, strip out pre-defined events from the host manifest's event log (when 'excludestags' are
//   present) and then subtract 'expected' from 'actual'. If the results are not empty, raise a
//   PcrEventLogContainsUnexpectedEntries fault.
// - Also report the missing events by subtracting 'actual' from 'expected' and raising a
//   PcrEventLogMissingExpectedEntries fault.
func (rule *pcrEventLogEquals) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = rule.ruleName
	result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

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

			// when component excludes are present, strip out the events
			if rule.excludeTags != nil {
				actualEventLog, err = rule.removeExcludedEvents(actualEventLog)
				if err != nil {
					return nil, err
				}
			}

			// now subtract out 'expected'
			unexpectedEventLogs, unexpectedFields, err := actualEventLog.Subtract(rule.expectedEventLogEntry)
			if err != nil {
				return nil, err
			}

			// if there are any remaining events, then there were unexpected entries...
			if len(unexpectedEventLogs.EventLogs) > 0 {
				result.Faults = append(result.Faults, newPcrEventLogContainsUnexpectedEntries(unexpectedEventLogs))
			}

			if len(unexpectedFields.EventLogs) > 0 {
				Pi := types.PcrIndex(actualEventLog.NewPCR.PcrIndex)

				mismatchInfo := hvs.MismatchField{

					Name:              constants.PcrEventLogUnexpectedFields,
					Description:       fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", actualEventLog.NewPCR.PcrIndex, actualEventLog.NewPCR.PcrBank, len(unexpectedFields.EventLogs)),
					PcrIndex:          &Pi,
					PcrBank:           &actualEventLog.NewPCR.PcrBank,
					UnexpectedEntries: unexpectedFields.EventLogs,
				}
				result.MismatchField = append(result.MismatchField, mismatchInfo)
			}

			// now, look the other way -- find events that are in actual but not expected (i.e. missing)
			missingEventLogs, missingFields, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
			if err != nil {
				return nil, err
			}

			if len(missingEventLogs.EventLogs) > 0 {
				result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEventLogs))
			}

			if len(missingFields.EventLogs) > 0 {
				Pi := types.PcrIndex(rule.expectedEventLogEntry.NewPCR.PcrIndex)

				mismatchInfo := hvs.MismatchField{

					Name:           constants.PcrEventLogMissingFields,
					Description:    fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", rule.expectedEventLogEntry.NewPCR.PcrIndex, rule.expectedEventLogEntry.NewPCR.PcrBank, len(missingFields.EventLogs)),
					PcrIndex:       &Pi,
					PcrBank:        &rule.expectedEventLogEntry.NewPCR.PcrBank,
					MissingEntries: missingFields.EventLogs,
				}
				result.MismatchField = append(result.MismatchField, mismatchInfo)
			}
		}
	}

	return &result, nil
}

// Creates a new EventLogEntry without events given in excludetags

func (rule *pcrEventLogEquals) removeExcludedEvents(eventLogEntry *types.NewFVEventLogEntry) (*types.NewFVEventLogEntry, error) {

	var eventsWithoutComponentName []types.NewFVEventLog

	// Loop through the each eventlog and see if it contains the tag given in excludetags[]
	// and if so, do not add it to the results eventlog.
	for _, eventLog := range eventLogEntry.EventLogs {

		excludeTagPresent := false

		for _, a := range rule.excludeTags {
			if eventLog.Tags != nil {
				for _, tags := range *eventLog.Tags {
					if a == tags {
						excludeTagPresent = true
						break
					}
				}
			}
			if excludeTagPresent {
				break
			}
		}

		if excludeTagPresent {
			log.Debugf("Excluding the evaluation of event tyoe '%s'", eventLog.TypeName)
			continue
		}
		eventsWithoutComponentName = append(eventsWithoutComponentName, eventLog)

	}

	return &types.NewFVEventLogEntry{
		NewPCR: types.NewPcr{
			PcrIndex: eventLogEntry.NewPCR.PcrIndex,
			PcrBank:  eventLogEntry.NewPCR.PcrBank,
		},
		EventLogs: eventsWithoutComponentName,
	}, nil
}
