/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
)

//SetDeploySoftwareManifestRoute registers routes for APIs that deploy software manifest to host
func SetDeploySoftwareManifestRoute(router *mux.Router, store *postgres.DataStore, htm domain.HostTrustManager,
	hcConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/deploy_software_manifest:SetDeploySoftwareManifestRoute() Entering")
	defer defaultLog.Trace("router/deploy_software_manifest:SetDeploySoftwareManifestRoute() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)

	hostCredentialStore := postgres.NewHostCredentialStore(store, hcConfig.DataEncryptionKey)
	hc := controllers.NewHostController(hostStore, hostStatusStore, flavorStore,
		flavorGroupStore, hostCredentialStore, htm, hcConfig)
	dsmController := controllers.NewDeploySoftwareManifestController(flavorStore, *hc)

	router.Handle("/rpc/deploy-software-manifest",
		ErrorHandler(permissionsHandler(ResponseHandler(dsmController.DeployManifest),
			[]string{constants.SoftwareFlavorDeploy}))).Methods("POST")

	return router
}
