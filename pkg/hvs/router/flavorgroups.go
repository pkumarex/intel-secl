/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
)

// SetFlavorGroupRoutes registers routes for flavorgroups
func SetFlavorGroupRoutes(router *mux.Router, store *postgres.DataStore, flavorgroupStore *postgres.FlavorGroupStore, hostTrustManager domain.HostTrustManager) *mux.Router {
	defaultLog.Trace("router/flavorgroups:SetFlavorGroupRoutes() Entering")
	defer defaultLog.Trace("router/flavorgroups:SetFlavorGroupRoutes() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	hostStore := postgres.NewHostStore(store)
	flavorgroupController := controllers.FlavorgroupController{
		FlavorGroupStore: flavorgroupStore,
		FlavorStore:      flavorStore,
		HostStore:        hostStore,
		HTManager:        hostTrustManager,
	}

	flavorGroupIdExpr := fmt.Sprintf("%s%s", "/flavorgroups/", validation.IdReg)
	router.Handle("/flavorgroups",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorgroupController.Create),
			[]string{constants.FlavorGroupCreate}))).Methods("POST")

	router.Handle("/flavorgroups",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorgroupController.Search),
			[]string{constants.FlavorGroupSearch}))).Methods("GET")

	router.Handle(flavorGroupIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorgroupController.Delete),
			[]string{constants.FlavorGroupDelete}))).Methods("DELETE")

	router.Handle(flavorGroupIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorgroupController.Retrieve),
			[]string{constants.FlavorGroupRetrieve}))).Methods("GET")

	// routes for FlavorGroupFlavorLink APIs
	fgFlavorLinkCreateSearchExpr := fmt.Sprintf("/flavorgroups/{fgID:%s}/flavors", validation.UUIDReg)
	fgFlavorLinkRetrieveDeleteExpr := fmt.Sprintf("/flavorgroups/{fgID:%s}/flavors/{fID:%s}", validation.UUIDReg, validation.UUIDReg)

	router.Handle(fgFlavorLinkCreateSearchExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorgroupController.AddFlavor),
			[]string{constants.FlavorGroupCreate}))).Methods("POST")

	router.Handle(fgFlavorLinkRetrieveDeleteExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorgroupController.RetrieveFlavor),
			[]string{constants.FlavorGroupRetrieve}))).Methods("GET")

	router.Handle(fgFlavorLinkRetrieveDeleteExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorgroupController.RemoveFlavor),
			[]string{constants.FlavorGroupDelete}))).Methods("DELETE")

	router.Handle(fgFlavorLinkCreateSearchExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorgroupController.SearchFlavors),
			[]string{constants.FlavorGroupSearch}))).Methods("GET")

	return router
}
