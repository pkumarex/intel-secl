/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	"os"
)

func CreateSerialNumberFileAndJWTDir() {
	log.Trace("tasks/common_test:CreateSerialNumberFileAndJWTDir() Entering")
	defer log.Trace("tasks/common_test:CreateSerialNumberFileAndJWTDir() Leaving")

	os.MkdirAll(constants.ConfigDir, os.ModePerm)
	os.MkdirAll(constants.TrustedJWTSigningCertsDir, os.ModePerm)
	os.MkdirAll(constants.RootCADirPath, os.ModePerm)
	os.MkdirAll(constants.IntermediateCADirPath, os.ModePerm)
	var file, _ = os.OpenFile(constants.SerialNumberPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	defer file.Close()
}
