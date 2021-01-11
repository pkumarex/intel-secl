/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/config"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/controllers"
	log "github.com/sirupsen/logrus"
)

// SetCertificatesRoutes is used to set the endpoints for certificate handling APIs
func SetCertificatesRoutes(router *mux.Router, config *config.Configuration) *mux.Router {
	log.Trace("router/certificates:SetCertificatesRoutes() Entering")
	defer log.Trace("router/certificates:SetCertificatesRoutes() Leaving")

	certController := controllers.CertificatesController{Config: config}
	router.HandleFunc("/certificates", certController.GetCertificates).Methods("POST")
	return router
}
