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

// SetFlavorTemplateRoutes registers routes for flavor template creation
func SetFlavorTemplateRoutes(router *mux.Router, store *postgres.DataStore, flavorGroupStore *postgres.FlavorGroupStore, certStore *models.CertificatesStore, hostTrustManager domain.HostTrustManager, flavorControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/flavortemplate_creation:SetFlavorTemplateRoutes() Entering")
	defer defaultLog.Trace("router/flavortemplate_creation:SetFlavorTemplateRoutes() Leaving")

	flavorTemplateStore := postgres.NewFlavorTemplateStore(store)

	flavorTemplateController := controllers.NewFlavorTemplateController(flavorTemplateStore, constants.CommonDefinitionsSchema, constants.FlavorTemplateSchema)

	flavorTemplateIdExpr := fmt.Sprintf("%s%s", "/flavor-templates/", validation.IdReg)

	router.Handle("/flavor-templates",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorTemplateController.Create),
			[]string{constants.FlavorTemplateCreate}))).Methods("POST")

	router.Handle(flavorTemplateIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorTemplateController.Retrieve),
			[]string{constants.FlavorTemplateRetrieve}))).Methods("GET")

	router.Handle("/flavor-templates",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorTemplateController.Search),
			[]string{constants.FlavorTemplateSearch}))).Methods("GET")

	router.Handle(flavorTemplateIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorTemplateController.Delete),
			[]string{constants.FlavorTemplateDelete}))).Methods("DELETE")

	return router
}
