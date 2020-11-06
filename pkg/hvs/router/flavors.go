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
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
)

// SetFlavorRoutes registers routes for flavors
func SetFlavorRoutes(router *mux.Router, store *postgres.DataStore, flavorGroupStore *postgres.FlavorGroupStore, certStore *models.CertificatesStore, hostTrustManager domain.HostTrustManager, flavorControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	tagCertStore := postgres.NewTagCertificateStore(store)
	flavorController := controllers.NewFlavorController(flavorStore, flavorGroupStore, hostStore, tagCertStore, hostTrustManager, certStore, flavorControllerConfig)

	flavorIdExpr := fmt.Sprintf("%s%s", "/flavors/", validation.IdReg)

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Create),
			[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
		Methods("POST")

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Search),
			[]string{constants.FlavorSearch}))).Methods("GET")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Delete),
			[]string{constants.FlavorDelete}))).Methods("DELETE")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Retrieve),
			[]string{constants.FlavorRetrieve}))).Methods("GET")

	return router
}
