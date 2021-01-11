/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"encoding/xml"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

func NewXmlMeasurementLogDigestEquals(expectedDigestAlgorithm string, flavorID uuid.UUID) (Rule, error) {

	rule := xmlMeasurementLogDigestEquals{
		flavorID:                flavorID,
		expectedDigestAlgorithm: expectedDigestAlgorithm,
	}

	return &rule, nil
}

type xmlMeasurementLogDigestEquals struct {
	expectedDigestAlgorithm string
	flavorID                uuid.UUID
}

// - If the xml event log is missing, create a XmlMeasurementLogMissing fault.
// - Otherwise, loop over all of the software measurements and make sure they
//   have 'expectedDigestAlgorithm', creating faults if they don't match.
func (rule *xmlMeasurementLogDigestEquals) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RuleXmlMeasurementsDigestEquals
	result.Rule.Markers = append(result.Rule.Markers, common.FlavorPartSoftware)

	if hostManifest.MeasurementXmls == nil || len(hostManifest.MeasurementXmls) == 0 {
		result.Faults = append(result.Faults, newXmlEventLogMissingFault(rule.flavorID))
	} else {
		for _, measurementXml := range hostManifest.MeasurementXmls {
			var measurement model.Measurement
			err := xml.Unmarshal([]byte(measurementXml), &measurement)
			if err != nil {
				result.Faults = append(result.Faults, newXmlMeasurementLogInvalidFault())
			} else {
				if measurement.DigestAlg != rule.expectedDigestAlgorithm {

					fault := hvs.Fault{
						Name:                 constants.FaultXmlMeasurementsDigestValueMismatch,
						Description:          fmt.Sprintf("XML measurement log for flavor %s has %s algorithm does not match with measurement %s - %s algorithm.", rule.flavorID, rule.expectedDigestAlgorithm, measurement.Uuid, measurement.DigestAlg),
						FlavorId:             &rule.flavorID,
						MeasurementDigestAlg: &measurement.DigestAlg,
						FlavorDigestAlg:      &rule.expectedDigestAlgorithm,
					}

					result.Faults = append(result.Faults, fault)
				}
			}
		}
	}

	return &result, nil
}
