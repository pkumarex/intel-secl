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
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
)

//SetFlavorFromAppManifestRoute registers routes for APIs that return software flavor from manifest
func SetFlavorFromAppManifestRoute(router *mux.Router, store *postgres.DataStore, flavorGroupStore *postgres.FlavorGroupStore, certStore *models.CertificatesStore,
	hostTrustManager domain.HostTrustManager, hcConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/flavor-from-app-manifest:SetFlavorFromAppManifestRoute() Entering")
	defer defaultLog.Trace("router/flavor-from-app-manifest:SetFlavorFromAppManifestRoute() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	hostStore := postgres.NewHostStore(store)
	tagCertStore := postgres.NewTagCertificateStore(store)
	flavorController := controllers.NewFlavorController(flavorStore, flavorGroupStore, hostStore, tagCertStore, hostTrustManager, certStore, hcConfig)
	flavorFromAppManifestController := controllers.NewFlavorFromAppManifestController(*flavorController)

	router.Handle("/flavor-from-app-manifest",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorFromAppManifestController.CreateSoftwareFlavor),
			[]string{constants.SoftwareFlavorCreate}))).Methods("POST")

	return router
}
