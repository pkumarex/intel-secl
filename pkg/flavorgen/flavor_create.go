/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavorgen

import (
	"encoding/json"
	"fmt"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commFlavor "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	flavorType "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

var defaultLog = commLog.GetDefaultLogger()

//create the flavorpart json
func createFlavor(platformFlavor flavorType.PlatformFlavor) error {
	defaultLog.Trace("flavorgen/flavor_create:createFlavor() Entering")
	defer defaultLog.Trace("flavorgen/flavor_create:createFlavor() Leaving")

	var flavors []hvs.Flavors
	var err error

	flavorParts := []commFlavor.FlavorPart{commFlavor.FlavorPartPlatform, commFlavor.FlavorPartOs, commFlavor.FlavorPartHostUnique}
	for _, flavorPart := range flavorParts {
		unSignedFlavors, err := platformFlavor.GetFlavorPartRaw(flavorPart)
		if err != nil {
			return errors.Wrapf(err, "flavorgen/flavor_create:createFlavor() Unable to create flavor part %s", flavorPart)
		}
		for _, flvr := range unSignedFlavors {
			flavor := hvs.Flavors{
				Flavor: flvr,
			}
			flavors = append(flavors, flavor)
		}
	}

	flavorCollection := hvs.FlavorCollection{
		Flavors: flavors,
	}

	flavorJSON, err := json.Marshal(flavorCollection)
	if err != nil {
		return errors.Wrapf(err, "flavorgen/flavor_create:createFlavor() Couldn't marshal signedflavorCollection")
	}
	flavorPartJSON := string(flavorJSON)
	fmt.Println(flavorPartJSON)

	return nil
}
