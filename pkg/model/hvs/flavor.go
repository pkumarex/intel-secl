/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
)

// Flavor sourced from the lib/flavor - this is a external request/response on the HVS API
type Flavor = model.Flavor

// FlavorFC sourced from the lib/flavor - this is a external request/response on the HVS API
type FlavorFC = model.FlavorFC

// FlavorCollection is a list of Flavor objects in response to a Flavor Search query
type FlavorCollection struct {
	Flavors []Flavors `json:"flavors"`
}

type FlavorCollectionFC struct {
	Flavors []FlavorsFC `json:"flavors"`
}

type Flavors struct {
	Flavor Flavor `json:"flavor"`
}

type FlavorsFC struct {
	Flavor FlavorFC `json:"flavor"`
}

// SignedFlavor sourced from the lib/flavor - this is a external request/response on the HVS API
type SignedFlavor = model.SignedFlavor

// SignedFlavor sourced from the lib/flavor - this is a external request/response on the HVS API
type SignedFlavorFC = model.SignedFlavorFC

// SignedFlavorCollection is a list of SignedFlavor objects
type SignedFlavorCollection struct {
	SignedFlavors []SignedFlavor `json:"signed_flavors"`
}

type SignedFlavorCollectionFC struct {
	SignedFlavors []SignedFlavorFC `json:"signed_flavors"`
}

func (s SignedFlavorCollection) GetFlavors(flavorPart string) []SignedFlavor {
	signedFlavors := []SignedFlavor{}
	for _, flavor := range s.SignedFlavors {
		if flavor.Flavor.Meta.Description[model.FlavorPart] == flavorPart {
			signedFlavors = append(signedFlavors, flavor)
		}
	}
	return signedFlavors
}
