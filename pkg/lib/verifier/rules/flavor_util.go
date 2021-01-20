/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"encoding/xml"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	flavor_model "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

// Utility function that finds the hvs.PcrEx at 'bank' and 'index' and returns
// the corresponding host-connector PCR value.  This is typically used by policies
// when creating rules from the flavor values.
func getPcrValueFromFlavor(flavor *hvs.Flavor, bank types.SHAAlgorithm, index types.PcrIndex) (*types.Pcr, error) {
	if flavor == nil {
		return nil, errors.New("The flavor cannot be nil")
	}

	pcrValue, err := flavor.GetPcrValue(bank, index)
	if err != nil {
		return nil, err
	}

	return FlavorPcr2ManifestPcr(pcrValue, bank, index)
}

func FlavorPcr2ManifestPcr(pcrEx *flavor_model.PcrEx, bank types.SHAAlgorithm, index types.PcrIndex) (*types.Pcr, error) {

	if pcrEx == nil {
		return nil, errors.New("The pcrex value cannot be nil")
	}

	return &types.Pcr{
		Index:   index,
		Value:   pcrEx.Value,
		PcrBank: bank,
	}, nil
}

// lookup the Measurement from the host manifest
func getMeasurementAssociatedWithFlavor(hostManifest *types.HostManifest, flavorId uuid.UUID, flavorLabel string) (*model.Measurement, []byte, error) {

	for i, measurementXml := range hostManifest.MeasurementXmls {
		var measurement model.Measurement
		xmlBytes := []byte(measurementXml)

		err := xml.Unmarshal(xmlBytes, &measurement)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "An error occurred parsing measurement xml index %d", i)
		}

		if flavorId.String() == measurement.Uuid {
			return &measurement, xmlBytes, nil
		}

		if (strings.Contains(flavorLabel, constants.DefaultSoftwareFlavorPrefix) ||
			strings.Contains(flavorLabel, constants.DefaultWorkloadFlavorPrefix)) && flavorLabel == measurement.Label {
			return &measurement, xmlBytes, nil
		}
	}

	// not an error, just return nil
	return nil, nil, nil
}
