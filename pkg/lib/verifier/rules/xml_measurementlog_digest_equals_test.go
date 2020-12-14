/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"encoding/xml"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	testUuid = uuid.New()
)

func TestXmlMeasurementLogDigestEqualsNoFault(t *testing.T) {

	// create the rule
	rule, err := NewXmlMeasurementLogDigestEquals(string(types.SHA384), testUuid)
	assert.NoError(t, err)

	// create a host manifest with a single measurement containing a valid SHA384
	// digest --> expect 'no faults'
	measurement := ta.Measurement{
		DigestAlg: string(types.SHA384),
		Uuid:      testUuid.String(),
	}

	measurementsXml, err := xml.Marshal(measurement)
	assert.NoError(t, err)

	hostManifest := types.HostManifest{
		MeasurementXmls: []string{string(measurementsXml)},
	}

	// apply the manifest to the rule and expect no faults/trusted
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Trusted)
	assert.Equal(t, len(result.Faults), 0)
}

func TestXmlMeasurementLogDigestEqualsFaultDigestValueMismatchFault(t *testing.T) {

	// create the rule
	rule, err := NewXmlMeasurementLogDigestEquals(string(types.SHA384), testUuid)
	assert.NoError(t, err)

	// create a host manifest with a one valid measurement and two invalid
	// measurements --> expect 2 XmlManifestDigetValueMismatch faults
	measurement := ta.Measurement{
		DigestAlg: string(types.SHA384),
		Uuid:      testUuid.String(),
	}

	measurementsXml, err := xml.Marshal(measurement)
	assert.NoError(t, err)

	invalidMeasurement := ta.Measurement{
		DigestAlg: string(types.SHA1),
		Uuid:      testUuid.String(),
	}

	invalidMeasurementsXml, err := xml.Marshal(invalidMeasurement)
	assert.NoError(t, err)

	hostManifest := types.HostManifest{
		MeasurementXmls: []string{
			string(measurementsXml),
			string(invalidMeasurementsXml),
			string(invalidMeasurementsXml),
		},
	}

	// apply the manifest to the rule and expect no faults/trusted
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 2, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementsDigestValueMismatch, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
