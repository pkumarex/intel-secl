/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

//
// Rule that compares the 'expected' PCR with the value stored in the host manifest.
//

import (
	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

//NewPcrMatchesConstant collects the expected PCR values
func NewPcrMatchesConstant(expectedPcr *types.FlavorPcrs, marker common.FlavorPart) (Rule, error) {
	var rule pcrMatchesConstant

	if expectedPcr == nil {
		return nil, errors.New("The expected PCR cannot be nil")
	}

	if len(expectedPcr.Measurement) < 1 {
		return nil, errors.New("The expected PCR cannot have an empty value")
	}

	rule = pcrMatchesConstant{
		expectedPcr: *expectedPcr,
		marker:      marker,
	}

	return &rule, nil
}

type pcrMatchesConstant struct {
	expectedPcr types.FlavorPcrs
	marker      common.FlavorPart
}

//Compare both the final hash of the expected and actual values
//If it mismatches,raise the faults
func (rule *pcrMatchesConstant) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true // default to true, set to false in fault logic
	result.Rule.Name = constants.RulePcrMatchesConstant
	result.Rule.PCR = &rule.expectedPcr.Pcr
	result.Rule.Measurement = rule.expectedPcr.Measurement
	result.Rule.PCRMatches = rule.expectedPcr.PCRMatches
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {
		actualPcr, err := hostManifest.PcrManifest.GetPcrValue(types.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), types.PcrIndex(rule.expectedPcr.Pcr.Index))
		if err != nil {
			return nil, errors.Wrap(err, "Error in getting actual Pcr in Pcr Matches constant rule")
		}

		if actualPcr == nil || actualPcr.Value == "" || rule.expectedPcr.Measurement == "" {
			result.Faults = append(result.Faults, newPcrValueMissingFault(types.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), types.PcrIndex(rule.expectedPcr.Pcr.Index)))
		} else if rule.expectedPcr.Measurement != actualPcr.Value {
			result.Faults = append(result.Faults, newPcrValueMismatchFault(types.PcrIndex(rule.expectedPcr.Pcr.Index), types.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), rule.expectedPcr, *actualPcr))
		}
	}

	return &result, nil
}
