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

// NewPcrEventLogIntegrity creates a rule that will check if a PCR (in the host-manifest only)
// has a "calculated hash" (i.e. from event log replay) that matches its actual hash.
func NewPcrEventLogIntegrity(expectedPcr *types.PCRS, marker common.FlavorPart) (Rule, error) {
	var rule pcrEventLogIntegrity

	if expectedPcr == nil {
		return nil, errors.New("The expected pcr cannot be nil")
	}

	rule = pcrEventLogIntegrity{
		expectedPcr: *expectedPcr,
		marker:      marker,
	}

	return &rule, nil
}

type pcrEventLogIntegrity struct {
	expectedPcr types.PCRS
	marker      common.FlavorPart
}

// - If the hostmanifest's PcrManifest is not present, create PcrManifestMissing fault.
// - If the hostmanifest does not contain a pcr at 'expected' bank/index, create a PcrValueMissing fault.
// - If the hostmanifest does not have an event log at 'expected' bank/index, create a
//   PcrEventLogMissing fault.
// - Otherwise, replay the hostmanifest's event log at 'expected' bank/index and verify the
//   the calculated hash matches the pcr value in the host-manifest.  If not, create a PcrEventLogInvalid fault.
func (rule *pcrEventLogIntegrity) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RulePcrEventLogIntegrity

	result.Rule.ExpectedPcr = &rule.expectedPcr
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {
		actualPcr, err := hostManifest.PcrManifest.GetPcrValue(types.SHAAlgorithm(rule.expectedPcr.PCR.Bank), types.PcrIndex(rule.expectedPcr.PCR.Index))
		if err != nil {
			return nil, errors.Wrap(err, "Error in getting actual Pcr in Pcr Eventlog Integrity rule")
		}

		if actualPcr == nil {
			result.Faults = append(result.Faults, newPcrValueMissingFault(types.SHAAlgorithm(rule.expectedPcr.PCR.Bank), types.PcrIndex(rule.expectedPcr.PCR.Index)))
		} else {
			actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMapLinux.GetEventLogNew(rule.expectedPcr.PCR.Bank, rule.expectedPcr.PCR.Index)
			if err != nil {
				return nil, errors.Wrap(err, "Error in getting actual eventlogs in Pcr Eventlog Integrity rule")
			}

			if actualEventLogCriteria == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(types.PcrIndex(rule.expectedPcr.PCR.Index), types.SHAAlgorithm(rule.expectedPcr.PCR.Bank)))
			} else {
				actualEventLog := &types.TpmEventLog{}
				actualEventLog.TpmEvent = actualEventLogCriteria
				actualEventLog.Pcr.Index = pIndex
				actualEventLog.Pcr.Bank = bank

				calculatedValue, err := actualEventLog.Replay()
				if err != nil {
					return nil, errors.Wrap(err, "Error in calculating replay in Pcr Eventlog Integrity rule")
				}

				if calculatedValue != actualPcr.Value {
					PI := types.PcrIndex(rule.expectedPcr.PCR.Index)
					fault := hvs.Fault{
						Name:            constants.FaultPcrEventLogInvalid,
						Description:     fmt.Sprintf("PCR %d Event Log is invalid,mismatches between calculated event log values %s and actual pcr values %s", rule.expectedPcr.PCR.Index, calculatedValue, actualPcr.Value),
						PcrIndex:        &PI,
						CalculatedValue: &calculatedValue,
						ActualPcrValue:  &actualPcr.Value,
					}
					result.Faults = append(result.Faults, fault)
				}
			}
		}
	}

	return &result, nil
}
