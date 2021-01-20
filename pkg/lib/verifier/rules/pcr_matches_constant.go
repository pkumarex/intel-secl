/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

//
// Rule that compares the 'expected' PCR with the value stored in the host manifest.
//

import (
	"reflect"

	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

//NewPcrMatchesConstant collects the expected PCR values
func NewPcrMatchesConstant(expectedPcr *types.Pcr, expectedPcrLog *types.PCRS, marker common.FlavorPart) (Rule, error) {
	var rule pcrMatchesConstant
	if expectedPcrLog != nil {

		if len(expectedPcrLog.Measurement) < 1 {
			return nil, errors.New("The expected PCR cannot have an empty value")
		}

		rule = pcrMatchesConstant{
			expectedPcrLog: *expectedPcrLog,
			marker:         marker,
		}
	} else if expectedPcr != nil {
		if len(expectedPcr.Value) == 0 {
			return nil, errors.New("The expected PCR cannot have an empty value")
		}

		rule = pcrMatchesConstant{
			expectedPcr: *expectedPcr,
			marker:      marker,
		}
	} else {
		return nil, errors.New("The expected PCR cannot be nil")
	}

	return &rule, nil
}

type pcrMatchesConstant struct {
	expectedPcr    types.Pcr
	expectedPcrLog types.PCRS
	marker         common.FlavorPart
}

//Compare both the final hash of the expected and actual values
//If it mismatches,raise the faults
func (rule *pcrMatchesConstant) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true // default to true, set to false in fault logic
	result.Rule.Name = constants.RulePcrMatchesConstant

	if !reflect.DeepEqual(rule.expectedPcrLog, types.PCRS{}) {
		result.Rule.PCR = &rule.expectedPcrLog.PCR
		result.Rule.Measurement = rule.expectedPcrLog.Measurement
		result.Rule.PCRMatches = rule.expectedPcrLog.PCRMatches
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {
			actualPcr, err := hostManifest.PcrManifest.GetPcrValue(types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank), types.PcrIndex(rule.expectedPcrLog.PCR.Index))
			if err != nil {
				return nil, errors.Wrap(err, "Error in getting actual Pcr in Pcr Matches constant rule")
			}

			if actualPcr == nil || actualPcr.Value == "" || rule.expectedPcrLog.Measurement == "" {
				result.Faults = append(result.Faults, newPcrValueMissingFault(types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank), types.PcrIndex(rule.expectedPcrLog.PCR.Index)))
			} else if rule.expectedPcrLog.Measurement != actualPcr.Value {
				result.Faults = append(result.Faults, newPcrValueMismatchFault(types.PcrIndex(rule.expectedPcrLog.PCR.Index), types.SHAAlgorithm(rule.expectedPcrLog.PCR.Bank), rule.expectedPcr, rule.expectedPcrLog, *actualPcr))
			}
		}
	} else {
		result.Rule.ExpectedPcr = &rule.expectedPcr
		result.Rule.Markers = append(result.Rule.Markers, rule.marker)

		if hostManifest.PcrManifest.IsEmpty() {
			result.Faults = append(result.Faults, newPcrManifestMissingFault())
		} else {
			actualPcr, err := hostManifest.PcrManifest.GetPcrValue(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
			if err != nil {
				return nil, errors.Wrap(err, "Error in retrieving the actual pcr value")
			}

			if actualPcr == nil {
				result.Faults = append(result.Faults, newPcrValueMissingFault(rule.expectedPcr.PcrBank, rule.expectedPcr.Index))
			} else if rule.expectedPcr.Value != actualPcr.Value {
				result.Faults = append(result.Faults, newPcrValueMismatchFault(rule.expectedPcr.Index, "", rule.expectedPcr, rule.expectedPcrLog, *actualPcr))
			}
		}
	}

	return &result, nil
}
