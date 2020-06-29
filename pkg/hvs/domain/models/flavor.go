/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type FlavorCreateCriteria struct {
	ConnectionString       string
	FlavorCollection       hvs.FlavorCollection
	SignedFlavorCollection hvs.SignedFlavorCollection
	FlavorgroupName        string
	FlavorParts            []string
}

//TODO: this struct will change when search store for hostManifest is created
type FlavorFilterCriteria struct {
	Id                    uuid.UUID
	Key                   string
	Value                 string
	FlavorGroupID         uuid.UUID
	FlavorParts           []cf.FlavorPart
	FlavorPartsWithLatest []cf.FlavorPart
	HostManifest          *hcTypes.HostManifest
}