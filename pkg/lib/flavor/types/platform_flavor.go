/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// PlatformFlavor interface must be implemented by specific PlatformFlavor
type PlatformFlavor interface {
	// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
	GetFlavorPartNames() ([]common.FlavorPart, error)

	// GetFlavorPartRaw extracts the details of the flavor part requested by the
	// caller from the host report used during the creation of the PlatformFlavor instance
	GetFlavorPartRaw(common.FlavorPart) ([]cm.Flavor, error)

	// GetFlavorPartRaw extracts the details of the flavor part requested by the
	// caller from the host report used during the creation of the PlatformFlavor instance
	GetFlavorPartRawFC(common.FlavorPart) ([]cm.FlavorFC, error)
}
