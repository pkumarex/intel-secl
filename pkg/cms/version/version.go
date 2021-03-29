/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
)

// Automatically filled in by linker

// Version holds the build revision for the CMS binary
var Version = ""

// GitHash holds the commit hash for the CMS binary
var GitHash = ""

// BuildDate holds the build timestamp for the CMS binary
var BuildDate = ""

func GetVersion() string {
	verStr := fmt.Sprintf("Service Name: %s\n", constants.ExplicitServiceName)
	verStr = verStr + fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	verStr = verStr + fmt.Sprintf("Build Date: %s\n", BuildDate)
	return verStr
}
