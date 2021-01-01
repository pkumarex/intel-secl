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

// NewPcrEventLogIntegrity creates a rule that will check if a PCR (in the host-manifest only)
// has a "calculated hash" (i.e. from event log replay) that matches its actual hash.
func NewPcrEventLogIntegrity(expectedPcrLog *types.PCRS, expectedPcr *types.Pcr, marker common.FlavorPart) (Rule, error) {

	var rule pcrEventLogIntegrity

	if expectedPcrLog != nil {
		rule = pcrEventLogIntegrity{
			expectedPcrLog: *expectedPcrLog,
			marker:         marker,
		}
	} else if expectedPcr != nil {
		rule = pcrEventLogIntegrity{
			expectedPcr: expectedPcr,
			marker:      marker,
		}
	} else {
		return nil, errors.New("The expected pcr cannot be nil")
	}
	return &rule, nil
}

type pcrEventLogIntegrity struct {
	expectedPcrLog types.PCRS
	expectedPcr    *types.Pcr
	marker         common.FlavorPart
}

// - If the hostmanifest's PcrManifest is not present, create PcrManifestMissing fault.
// - If the hostmanifest does not contain a pcr at 'expected' bank/index, create a PcrValueMissing fault.
// - If the hostmanifest does not have an event log at 'expected' bank/index, create a
//   PcrEventLogMissing fault.
// - Otherwise, replay the hostmanifest's event log at 'expected' bank/index and verify the
//   the calculated hash matches the pcr value in the host-manifest.  If not, crete a PcrEventLogInvalid fault.
func (rule *pcrEventLogIntegrity) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RulePcrEventLogIntegrity

	if !reflect.DeepEqual(rule.expectedPcrLog, types.PCRS{}) {
		result.Rule.ExpectedPcrLog = &rule.expectedPcrLog
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualPcr, err := hostManifest.PcrManifest.GetPcrValue(types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank), types.PcrIndex(rule.expectedPcrLog.PCR.Index))
			if err != nil {
				return nil, errors.Wrap(err, "Error in getting actual Pcr in Pcr Eventlog Integrity rule")
			}

			if actualPcr == nil {
				result.Faults = append(result.Faults, newPcrValueMissingFault(types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank), types.PcrIndex(rule.expectedPcrLog.PCR.Index)))
			} else {
				actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMapNew.GetEventLogNew(types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank), types.PcrIndex(rule.expectedPcrLog.PCR.Index))
				if err != nil {
					return nil, errors.Wrap(err, "Error in getting actual eventlogs in Pcr Eventlog Integrity rule")
				}

				if actualEventLogCriteria == nil {
					result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedPcrLog.PCR.Index), types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank)))
				} else {
					actualEventLog := &types.EventLogEntry{}
					actualEventLog.PcrEventLogs = *actualEventLogCriteria
					actualEventLog.PcrIndex = pIndex
					actualEventLog.PcrBank = bank

					calculatedValue, err := actualEventLog.Replay()
					if err != nil {
						return nil, errors.Wrap(err, "Error in calculating replay in Pcr Eventlog Integrity rule")
					}

					if calculatedValue != actualPcr.Value {
						PI := types.PcrIndex(rule.expectedPcrLog.PCR.Index)
						fault := hvs.Fault{
							Name:           constants.FaultPcrEventLogInvalid,
							Description:    fmt.Sprintf("PCR %d Event Log is invalid,mismatches between calculated event log values %s and actual pcr values %s", rule.expectedPcrLog.PCR.Index, calculatedValue, actualPcr.Value),
							PcrIndex:       &PI,
							ExpectedValue:  &calculatedValue,
							ActualPcrValue: &actualPcr.Value,
						}

						result.Faults = append(result.Faults, fault)
					}
				}
			}
		}
	} else {
		result.Rule.ExpectedPcr = rule.expectedPcr
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {

			actualPcr, err := hostManifest.PcrManifest.GetPcrValue(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
			if err != nil {
				return nil, err
			}

			if actualPcr == nil {
				result.Faults = append(result.Faults, newPcrValueMissingFault(rule.expectedPcr.PcrBank, rule.expectedPcr.Index))
			} else {
				actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
				if err != nil {
					return nil, err
				}

				if actualEventLog == nil {
					result.Faults = append(result.Faults, newPcrEventLogMissingFault(rule.expectedPcr.Index, rule.expectedPcr.PcrBank))
				} else {
					calculatedValue, err := actualEventLog.Replay()
					if err != nil {
						return nil, err
					}

					if calculatedValue != actualPcr.Value {
						fault := hvs.Fault{
							Name:        constants.FaultPcrEventLogInvalid,
							Description: fmt.Sprintf("PCR %d Event Log is invalid", rule.expectedPcr.Index),
							PcrIndex:    &rule.expectedPcr.Index,
						}

						result.Faults = append(result.Faults, fault)
					}
				}
			}
		}
	}
	return &result, nil
}
