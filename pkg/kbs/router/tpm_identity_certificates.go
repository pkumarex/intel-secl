/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/directory"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
)

//setTpmIdentityCertRoutes registers routes to perform TpmIdentityCertificate CRUD operations
func setTpmIdentityCertRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/tpm_identity_certificates:setTpmIdentityCertRoutes() Entering")
	defer defaultLog.Trace("router/tpm_identity_certificates:setTpmIdentityCertRoutes() Leaving")

	certStore := directory.NewCertificateStore(constants.TpmIdentityCertsDir)
	tpmIdentityCertController := controllers.NewCertificateController(certStore)
	certIdExpr := "/tpm-identity-certificates/" + validation.IdReg

	router.Handle("/tpm-identity-certificates", ErrorHandler(permissionsHandler(JsonResponseHandler(tpmIdentityCertController.Import),
		[]string{constants.TpmIdentityCertCreate}))).Methods("POST")

	router.Handle(certIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(tpmIdentityCertController.Retrieve),
		[]string{constants.TpmIdentityCertRetrieve}))).Methods("GET")

	router.Handle(certIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(tpmIdentityCertController.Delete),
		[]string{constants.TpmIdentityCertDelete}))).Methods("DELETE")

	router.Handle("/tpm-identity-certificates", ErrorHandler(permissionsHandler(JsonResponseHandler(tpmIdentityCertController.Search),
		[]string{constants.TpmIdentityCertSearch}))).Methods("GET")

	return router
}
