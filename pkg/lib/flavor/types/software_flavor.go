/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"encoding/xml"

	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// SoftwareFlavor represents a flavor consisting primarily of the integrity measurements taken on Software environment
// of the target host
type SoftwareFlavor struct {
	Measurement string `json:"measurement"`
}

// NewSoftwareFlavor returns an instance of SoftwareFlavor
func NewSoftwareFlavor(measurement string) SoftwareFlavor {
	return SoftwareFlavor{Measurement: measurement}
}

// GetSoftwareFlavor creates a SoftwareFlavor that would include all the measurements provided in input.
func (sf *SoftwareFlavor) GetSoftwareFlavor() (*cm.Flavor, error) {
	log.Trace("flavor/types/software_flavor:GetSoftwareFlavor() Entering")
	defer log.Trace("flavor/types/software_flavor:GetSoftwareFlavor() Leaving")

	var errorMessage = "Error during creation of SOFTWARE flavor"
	var measurements taModel.Measurement
	var err error
	err = xml.Unmarshal([]byte(sf.Measurement), &measurements)
	if err != nil {
		return nil, err
	}
	var software = sfutil.GetSoftware(measurements)
	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(nil, nil, sf.Measurement, cf.FlavorPartSoftware,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/software_flavor:GetSoftwareFlavor() New Meta Section: %v", *newMeta)

	return cm.NewFlavor(newMeta, nil, nil, nil, nil, &software), nil
}

// GetSoftwareFlavor creates a SoftwareFlavor that would include all the measurements provided in input.
func (sf *SoftwareFlavor) GetSoftwareFlavorFC() (*cm.FlavorFC, error) {
	log.Trace("flavor/types/software_flavor:GetSoftwareFlavor() Entering")
	defer log.Trace("flavor/types/software_flavor:GetSoftwareFlavor() Leaving")

	var errorMessage = "Error during creation of SOFTWARE flavor"
	var measurements taModel.Measurement
	var err error
	err = xml.Unmarshal([]byte(sf.Measurement), &measurements)
	if err != nil {
		return nil, err
	}
	var software = sfutil.GetSoftware(measurements)
	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(nil, nil, sf.Measurement, cf.FlavorPartSoftware,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/software_flavor:GetSoftwareFlavor() New Meta Section: %v", *newMeta)

	return cm.NewFlavorFC(newMeta, nil, nil, nil, nil, &software), nil
}
