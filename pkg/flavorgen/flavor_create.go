/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavorgen

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	flavorUtil "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commFlavor "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	flavorType "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

var defaultLog = commLog.GetDefaultLogger()

//create the flavorpart json
func createFlavor(linuxPlatformFlavor flavorType.PlatformFlavor) error {
	defaultLog.Trace("flavorgen/flavor_create:createFlavor() Entering")
	defer defaultLog.Trace("flavorgen/flavor_create:createFlavor() Leaving")

	var flavors []hvs.SignedFlavor

	flavorParts := []commFlavor.FlavorPart{commFlavor.FlavorPartPlatform, commFlavor.FlavorPartOs, commFlavor.FlavorPartHostUnique}

	flavorSignKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return errors.Wrap(err, "flavorgen/flavor_create:createFlavor() Couldn't generate RSA key, failed to create flavorsinging key")
	}

	for _, flavorPart := range flavorParts {
		unSignedFlavors, err := linuxPlatformFlavor.GetFlavorPartRaw(flavorPart)
		if err != nil {
			return errors.Wrapf(err, "flavorgen/flavor_create:createFlavor() Unable to create flavor part %s", flavorPart)
		}
		signedFlavors, err := flavorUtil.PlatformFlavorUtil{}.GetSignedFlavorList(unSignedFlavors, flavorSignKey)
		if err != nil {
			return errors.Wrapf(err, "flavorgen/flavor_create:createFlavor() Failed to create signed flavor %s", flavorPart)
		}
		flavors = append(flavors, signedFlavors...)
	}

	signedFlavorCollection := hvs.SignedFlavorCollection{
		SignedFlavors: flavors,
	}

	flavorJSON, err := json.Marshal(signedFlavorCollection)
	if err != nil {
		return errors.Wrapf(err, "flavorgen/flavor_create:createFlavor() Couldn't marshal signedflavorCollection")
	}
	flavorPartJSON := string(flavorJSON)
	fmt.Println(flavorPartJSON)

	return nil
}
