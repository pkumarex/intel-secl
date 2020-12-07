/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
)

func SetVersionRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:SetVersionRoutes() Entering")
	defer defaultLog.Trace("router/version:SetVersionRoutes() Leaving")
	versionController := controllers.VersionController{}

	router.Handle("/version", ErrorHandler(ResponseHandler(versionController.GetVersion))).Methods("GET")
	return router
}