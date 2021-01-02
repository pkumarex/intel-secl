/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

var (
	// This is a map of component names to remove the host manifest's list of events.  The
	// map value (int) is not relevant, just use the map key for efficient lookups.
	defaultExcludeComponents = map[string]int{
		"commandLine.":              0,
		"LCP_CONTROL_HASH":          0,
		"initrd":                    0,
		"vmlinuz":                   0,
		"componentName.imgdb.tgz":   0,
		"componentName.onetime.tgz": 0,
	}

	// map of 'labels' to exclude during the evaluation of the host manifest
	defaultExcludeLabels = map[string]int{
		"0x4fe": 0,
	}
)

// NewPcrEventLogEquals create the rule without the ExcludeTags,Components/labels
// so that all events are evaluated (i.e. no 'excludes').
func NewPcrEventLogEquals(expectedEventLogEntry *types.EventLogEntry, expectedPcrEventLogEntry *types.EventLogEntryFC, flavorID uuid.UUID, marker common.FlavorPart) (Rule, error) {

	// create

	var rule pcrEventLogEquals

	if expectedEventLogEntry != nil {
		rule = pcrEventLogEquals{
			expectedEventLogEntry: expectedEventLogEntry,
			ruleName:              constants.RulePcrEventLogEquals,
			flavorID:              &flavorID,
			marker:                marker,
		}
	} else {
		rule = pcrEventLogEquals{
			expectedPcrEventLogEntry: expectedPcrEventLogEntry,
			ruleName:                 constants.RulePcrEventLogEquals,
			flavorID:                 &flavorID,
			marker:                   marker,
		}
	}

	return &rule, nil
}

//NewPcrEventLogEqualsExcluding create the rule providing the Exclude tags,Components and labels
//so they are not included for evaluation during 'Apply'.
func NewPcrEventLogEqualsExcluding(expectedEventLogEntry *types.EventLogEntry, expectedPcrEventLogEntry *types.EventLogEntryFC, expectedPcr *types.Pcr, excludedEvents []string, flavorID uuid.UUID, marker common.FlavorPart) (Rule, error) {

	var rule pcrEventLogEquals

	if expectedEventLogEntry != nil {
		rule = pcrEventLogEquals{
			expectedEventLogEntry: expectedEventLogEntry,
			expectedPcr:           expectedPcr,
			flavorID:              &flavorID,
			marker:                marker,
			excludeComponents:     defaultExcludeComponents,
			excludeLabels:         defaultExcludeLabels,
			ruleName:              constants.RulePcrEventLogEqualsExcluding,
		}
	} else {
		rule = pcrEventLogEquals{
			expectedPcrEventLogEntry: expectedPcrEventLogEntry,
			excludeTags:              excludedEvents,
			flavorID:                 &flavorID,
			marker:                   marker,
			ruleName:                 constants.RulePcrEventLogEqualsExcluding,
		}
	}

	return &rule, nil
}

type pcrEventLogEquals struct {
	expectedEventLogEntry    *types.EventLogEntry
	expectedPcrEventLogEntry *types.EventLogEntryFC
	expectedPcr              *types.Pcr
	flavorID                 *uuid.UUID
	marker                   common.FlavorPart
	ruleName                 string
	excludeTags              []string
	excludeComponents        map[string]int
	excludeLabels            map[string]int
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

	if rule.expectedPcrEventLogEntry != nil {
		result.Rule.ExpectedPcrEventLogEntry = rule.expectedPcrEventLogEntry
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMapNew.GetEventLogNew(rule.expectedPcrEventLogEntry.Pcr.Bank, rule.expectedPcrEventLogEntry.Pcr.Index)
			if err != nil {
				return nil, errors.Wrap(err, "Error in retrieving the actual event log values in pcr eventlog equals rule")
			}

			if actualEventLogCriteria == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index), types.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)))
			} else {
				actualEventLog := &types.EventLogEntryFC{}
				actualEventLog.TpmEvent = actualEventLogCriteria
				actualEventLog.Pcr.Index = pIndex
				actualEventLog.Pcr.Bank = bank

				// when component excludes are present, strip out the events
				if rule.excludeTags != nil {
					_, actualEventLog, err = rule.removeExcludedEvents(nil, actualEventLog)
					if err != nil {
						return nil, errors.Wrap(err, "Error in removing the exclude tags from actual event log in pcr eventlog equals rule")
					}
				}

				// now subtract out 'expected'
				unexpectedEventLogs, unexpectedFields, err := actualEventLog.Subtract(rule.expectedPcrEventLogEntry)
				if err != nil {
					return nil, errors.Wrap(err, "Error in subtracting expected event logs from actual in pcr eventlog equals rule")
				}

				// if there are any remaining events, then there were unexpected entries...
				if len(unexpectedEventLogs.TpmEvent) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogContainsUnexpectedEntries(nil, unexpectedEventLogs))
				}

				if len(unexpectedFields.TpmEvent) > 0 {
					pcrIndex := types.PcrIndex(actualEventLog.Pcr.Index)
					pcrBank := types.SHAAlgorithm(actualEventLog.Pcr.Bank)

					mismatchInfo := hvs.MismatchField{

						Name:              constants.PcrEventLogUnexpectedFields,
						Description:       fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", actualEventLog.Pcr.Index, actualEventLog.Pcr.Bank, len(unexpectedFields.TpmEvent)),
						PcrIndex:          &pcrIndex,
						PcrBank:           &pcrBank,
						UnexpectedEntries: unexpectedFields.TpmEvent,
					}
					result.MismatchField = append(result.MismatchField, mismatchInfo)
				}

				// now, look the other way -- find events that are in actual but not expected (i.e. missing)
				missingEventLogs, missingFields, err := rule.expectedPcrEventLogEntry.Subtract(actualEventLog)
				if err != nil {
					return nil, errors.Wrap(err, "Error in subtracting actual event logs from expected in pcr eventlog equals rule")
				}

				if len(missingEventLogs.TpmEvent) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(nil, missingEventLogs))
				}

				if len(missingFields.TpmEvent) > 0 {
					pcrIndex := types.PcrIndex(rule.expectedEventLogEntry.PcrIndex)
					pcrBank := types.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)

					mismatchInfo := hvs.MismatchField{

						Name:           constants.PcrEventLogMissingFields,
						Description:    fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", rule.expectedPcrEventLogEntry.Pcr.Index, rule.expectedPcrEventLogEntry.Pcr.Bank, len(missingFields.TpmEvent)),
						PcrIndex:       &pcrIndex,
						PcrBank:        &pcrBank,
						MissingEntries: missingFields.TpmEvent,
					}
					result.MismatchField = append(result.MismatchField, mismatchInfo)
				}
			}
		}
	} else {
		result.Rule.ExpectedPcr = rule.expectedPcr
		result.Rule.ExpectedEventLogEntry = rule.expectedEventLogEntry
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
			if err != nil {
				return nil, errors.Wrap(err, "Error in retrieving the actual event log values in pcr eventlog equals rule")
			}

			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(rule.expectedEventLogEntry.PcrIndex, rule.expectedEventLogEntry.PcrBank))
			} else {

				// when component excludes are present, strip out the events with the component names
				if rule.excludeComponents != nil {
					actualEventLog, _, err = rule.removeExcludedEvents(actualEventLog, nil)
					if err != nil {
						return nil, errors.Wrap(err, "Error in removing exclude tags from actual event log in pcr eventlog equals rule")
					}
				}

				// when label exludes are present, strip out the events with the label values
				if rule.excludeLabels != nil {
					actualEventLog, err = rule.removeEventsWithLabel(actualEventLog)
					if err != nil {
						return nil, errors.Wrap(err, "Error in removing exclude labels from actual event log in pcr eventlog equals rule")
					}
				}

				// now subtract out 'expected'
				unexpectedEventLogs, err := actualEventLog.Subtract(rule.expectedEventLogEntry)
				if err != nil {
					return nil, errors.Wrap(err, "Error in subtracting expected from actual event log in pcr eventlog equals rule")
				}

				// if there are any remaining events, then there were unexpected entries...
				if len(unexpectedEventLogs.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogContainsUnexpectedEntries(unexpectedEventLogs, nil))
				}

				// now, look the other way -- find events that are in actual but not expected (i.e. missing)
				missingEventLogs, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
				if err != nil {
					return nil, errors.Wrap(err, "Error in subtracting actual from expected event log in pcr eventlog equals rule")
				}

				if len(missingEventLogs.EventLogs) > 0 {
					result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEventLogs, nil))
				}
			}
		}
	}

	return &result, nil
}

// Creates a new EventLogEntry without events given in excludetags

func (rule *pcrEventLogEquals) removeExcludedEvents(eventLogEntry *types.EventLogEntry, pcrEventLogEntry *types.EventLogEntryFC) (*types.EventLogEntry, *types.EventLogEntryFC, error) {

	var eventLogs *types.EventLogEntry
	var pcrEventLogs *types.EventLogEntryFC

	if pcrEventLogEntry != nil {
		var eventsWithoutComponentName []types.EventLogCriteria

		// Loop through the each eventlog and see if it contains the tag given in excludetags[]
		// and if so, do not add it to the results eventlog.
		for _, eventLog := range pcrEventLogEntry.TpmEvent {

			excludeTagPresent := false

			for _, a := range rule.excludeTags {
				if eventLog.Tags != nil {
					for _, tags := range eventLog.Tags {
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

		pcrEventLogs = &types.EventLogEntryFC{
			Pcr: types.PCR{
				Index: pcrEventLogEntry.Pcr.Index,
				Bank:  pcrEventLogEntry.Pcr.Bank,
			},
			TpmEvent: eventsWithoutComponentName,
		}
		return nil, pcrEventLogs, nil
	} else {
		var eventsWithoutComponentName []types.EventLog

		// Loop through the each eventlog and see if it contains a ComponentName key/value.
		// If it does, see if the ComponentName exists in the 'componentNamesToExclude' map,
		// and if so, do not add it to the results eventlog.
		for _, eventLog := range eventLogEntry.EventLogs {
			if componentName, ok := eventLog.Info["ComponentName"]; ok {
				if _, ok := rule.excludeComponents[componentName]; ok {
					log.Debugf("Excluding the evaluation of event log '%s' with component name '%s'", eventLog.Label, componentName)
					continue
				}
			}

			// Also, do not add event logs where the PackageName and PackageVendor are present
			// but empty (ex. {"Packagename":""}).
			if packageName, ok := eventLog.Info["PackageName"]; ok && len(packageName) == 0 {
				if packageVendor, ok := eventLog.Info["PackageVendor"]; ok && len(packageVendor) == 0 {
					log.Debugf("Excluding the evaluation of event log '%s' with empty package name and vendor", eventLog.Label)
					continue
				}
			}

			eventsWithoutComponentName = append(eventsWithoutComponentName, eventLog)
		}
		eventLogs = &types.EventLogEntry{
			PcrIndex:  eventLogEntry.PcrIndex,
			PcrBank:   eventLogEntry.PcrBank,
			EventLogs: eventsWithoutComponentName,
		}
		return eventLogs, nil, nil
	}

	return nil, nil, nil
}

// Creates a new EventLogEntry without events where EventLog.label matches 'label'
func (rule *pcrEventLogEquals) removeEventsWithLabel(eventLogEntry *types.EventLogEntry) (*types.EventLogEntry, error) {

	var eventsWithoutLabel []types.EventLog

	for _, eventLog := range eventLogEntry.EventLogs {
		if _, ok := rule.excludeLabels[eventLog.Label]; ok {
			log.Debugf("Excluding the evaluation of event log with label '%s'", eventLog.Label)
			continue
		}

		eventsWithoutLabel = append(eventsWithoutLabel, eventLog)
	}

	return &types.EventLogEntry{
		PcrIndex:  eventLogEntry.PcrIndex,
		PcrBank:   eventLogEntry.PcrBank,
		EventLogs: eventsWithoutLabel,
	}, nil
}
