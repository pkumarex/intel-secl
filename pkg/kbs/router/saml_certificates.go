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

//setSamlCertRoutes registers routes to perform SamlCertificate CRUD operations
func setSamlCertRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/saml_certificates:setSamlCertRoutes() Entering")
	defer defaultLog.Trace("router/saml_certificates:setSamlCertRoutes() Leaving")

	certStore := directory.NewCertificateStore(constants.SamlCertsDir)
	samlCertController := controllers.NewCertificateController(certStore)
	certIdExpr := "/saml-certificates/" + validation.IdReg

	router.Handle("/saml-certificates", ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Import),
		[]string{constants.SamlCertCreate}))).Methods("POST")

	router.Handle(certIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Retrieve),
			[]string{constants.SamlCertRetrieve}))).Methods("GET")

	router.Handle(certIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Delete),
			[]string{constants.SamlCertDelete}))).Methods("DELETE")

	router.Handle("/saml-certificates", ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Search),
		[]string{constants.SamlCertSearch}))).Methods("GET")

	return router
}
