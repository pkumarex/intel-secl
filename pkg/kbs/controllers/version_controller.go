/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"fmt"
	"net/http"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/version"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type VersionController struct {
}

//GetVersion : Function to get version of kbs
func (controller VersionController) GetVersion(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/version_controller:GetVersion() Entering")
	defer defaultLog.Trace("controllers/version_controller:GetVersion() Leaving")
	verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	return verStr, http.StatusOK, nil
}
