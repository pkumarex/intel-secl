/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/controllers"
)

func setVersionRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:setVersionRoutes() Entering")
	defer defaultLog.Trace("router/version:setVersionRoutes() Leaving")
	versionController := controllers.VersionController{}

	router.Handle("/version", ErrorHandler(ResponseHandler(versionController.GetVersion))).Methods("GET")
	return router
}
