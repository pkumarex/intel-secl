/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/controllers"
)

func SetVersionRoutes(r *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:SetVersion() Entering")
	defer defaultLog.Trace("router/version:SetVersion() Leaving")

	controller := controllers.VersionController{}
	r.Handle("/version", ErrorHandler(ResponseHandler(controller.GetVersion, ""))).Methods("GET")
	return r
}
