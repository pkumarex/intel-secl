/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
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

// SetESXiClusterRoutes registers routes for esxi cluster apis
func SetESXiClusterRoutes(router *mux.Router, store *postgres.DataStore,
	hostTrustManager domain.HostTrustManager, hostControllerConfig domain.HostControllerConfig) *mux.Router {

	defaultLog.Trace("router/esxi_cluster:SetESXiClusterRoutes() Entering")
	defer defaultLog.Trace("router/esxi_cluster:SetESXiClusterRoutes() Leaving")

	esxiClusterStore := postgres.NewESXiCLusterStore(store, hostControllerConfig.DataEncryptionKey)
	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostCredentialStore := postgres.NewHostCredentialStore(store, hostControllerConfig.DataEncryptionKey)
	hc := controllers.NewHostController(hostStore, hostStatusStore, flavorStore,
		flavorGroupStore, hostCredentialStore, hostTrustManager, hostControllerConfig)
	esxiClusterController := controllers.NewESXiClusterController(esxiClusterStore, *hc)

	esxiClusterIdExpr := fmt.Sprintf("%s%s", "/esxi-cluster/", validation.IdReg)

	router.Handle("/esxi-cluster",
		ErrorHandler(permissionsHandler(JsonResponseHandler(esxiClusterController.Create),
			[]string{constants.ESXiClusterCreate}))).Methods("POST")

	router.Handle("/esxi-cluster",
		ErrorHandler(permissionsHandler(JsonResponseHandler(esxiClusterController.Search),
			[]string{constants.ESXiClusterSearch}))).Methods("GET")

	router.Handle(esxiClusterIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(esxiClusterController.Delete),
			[]string{constants.ESXiClusterDelete}))).Methods("DELETE")

	router.Handle(esxiClusterIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(esxiClusterController.Retrieve),
			[]string{constants.ESXiClusterRetrieve}))).Methods("GET")

	return router
}
