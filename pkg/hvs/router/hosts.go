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

// SetHostRoutes registers routes for hosts
func SetHostRoutes(router *mux.Router, store *postgres.DataStore, hostTrustManager domain.HostTrustManager, hostControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/hosts:SetHostRoutes() Entering")
	defer defaultLog.Trace("router/hosts:SetHostRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostCredentialStore := postgres.NewHostCredentialStore(store, hostControllerConfig.DataEncryptionKey)

	hostController := controllers.NewHostController(hostStore, hostStatusStore,
		flavorStore, flavorGroupStore, hostCredentialStore,
		hostTrustManager, hostControllerConfig)

	hostExpr := "/hosts"
	hostIdExpr := fmt.Sprintf("%s/{hId:%s}", hostExpr, validation.UUIDReg)
	flavorgroupExpr := fmt.Sprintf("%s/flavorgroups", hostIdExpr)
	flavorgroupIdExpr := fmt.Sprintf("%s/{fgId:%s}", flavorgroupExpr, validation.UUIDReg)

	router.Handle(hostExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.Create),
		[]string{constants.HostCreate}))).Methods("POST")
	router.Handle(hostIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.Retrieve),
		[]string{constants.HostRetrieve}))).Methods("GET")
	router.Handle(hostIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.Update),
		[]string{constants.HostUpdate}))).Methods("PUT")
	router.Handle(hostIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(hostController.Delete),
		[]string{constants.HostDelete}))).Methods("DELETE")
	router.Handle(hostExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.Search),
		[]string{constants.HostSearch}))).Methods("GET")

	router.Handle(flavorgroupExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.AddFlavorgroup),
		[]string{constants.HostCreate}))).Methods("POST")
	router.Handle(flavorgroupIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.RetrieveFlavorgroup),
		[]string{constants.HostRetrieve}))).Methods("GET")
	router.Handle(flavorgroupIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(hostController.RemoveFlavorgroup),
		[]string{constants.HostDelete}))).Methods("DELETE")
	router.Handle(flavorgroupExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(hostController.SearchFlavorgroups),
		[]string{constants.HostSearch}))).Methods("GET")

	return router
}
