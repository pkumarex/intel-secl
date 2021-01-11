/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
)

func SetCertifyHostKeysRoutes(router *mux.Router, certStore *models.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/certify_host_keys:SetCertifyHostKeys() Entering")
	defer defaultLog.Trace("router/certify_host_keys:SetCertifyHostKeys() Leaving")

	certifyHostKeysController := controllers.NewCertifyHostKeysController(certStore)
	if certifyHostKeysController == nil {
		defaultLog.Error("router/certify_host_keys:SetCertifyHostKeys() Could not instantiate CertifyHostKeysController")
	}
	router.HandleFunc("/rpc/certify-host-signing-key", ErrorHandler(permissionsHandler(JsonResponseHandler(certifyHostKeysController.CertifySigningKey), []string{consts.CertifyHostSigningKey}))).Methods("POST")
	router.HandleFunc("/rpc/certify-host-binding-key", ErrorHandler(permissionsHandler(JsonResponseHandler(certifyHostKeysController.CertifyBindingKey), []string{consts.CertifyHostSigningKey}))).Methods("POST")
	return router
}

func SetCertifyAiksRoutes(router *mux.Router, store *postgres.DataStore, certStore *models.CertificatesStore, aikCertValidity int) *mux.Router {
	defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Entering")
	defer defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Leaving")

	tpmEndorsementStore := postgres.NewTpmEndorsementStore(store)
	certifyHostAiksController := controllers.NewCertifyHostAiksController(certStore, tpmEndorsementStore, aikCertValidity, consts.AikRequestsDir)
	if certifyHostAiksController != nil {
		router.Handle("/privacyca/identity-challenge-request", ErrorHandler(permissionsHandler(JsonResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge),
			[]string{consts.CertifyAik}))).Methods("POST")
		router.Handle("/privacyca/identity-challenge-response", ErrorHandler(permissionsHandler(JsonResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse),
			[]string{consts.CertifyAik}))).Methods("POST")
	}
	return router
}
