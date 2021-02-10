/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	jwtauth "github.com/intel-secl/intel-secl/v3/pkg/lib/common/jwt"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/config"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	cmw "github.com/intel-secl/intel-secl/v3/pkg/lib/common/middleware"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type Router struct {
	cfg *config.Configuration
}

// InitRoutes registers all routes for the application.
func InitRoutes(cfg *config.Configuration, dataStore *postgres.PostgresDatabase,
	tokenFactory *jwtauth.JwtFactory) *mux.Router {
	defaultLog.Trace("router/router:InitRoutes() Entering")
	defer defaultLog.Trace("router/router:InitRoutes() Leaving")

	// Create public routes that does not need any authentication
	router := mux.NewRouter()

	// ISECL-8715 - Prevent potential open redirects to external URLs
	router.SkipClean(true)
	defineSubRoutes(router, strings.ToLower(constants.ServiceName), cfg, dataStore, tokenFactory)
	return router
}

func defineSubRoutes(router *mux.Router, service string, cfg *config.Configuration, dataStore *postgres.PostgresDatabase,
	tokenFactory *jwtauth.JwtFactory) {
	defaultLog.Trace("router/router:defineSubRoutes() Entering")
	defer defaultLog.Trace("router/router:defineSubRoutes() Leaving")

	serviceApi := "/" + service + "/" + constants.ApiVersion
	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = SetVersionRoutes(subRouter)
	subRouter = SetJwtCertificateRoutes(subRouter)

	subRouter = router.PathPrefix(serviceApi).Subrouter()
	subRouter = SetJwtTokenRoutes(subRouter, dataStore, tokenFactory)
	subRouter = SetUsersNoAuthRoutes(subRouter, dataStore)

	subRouter = router.PathPrefix(serviceApi).Subrouter()
	cfgRouter := Router{cfg: cfg}
	subRouter.Use(cmw.NewTokenAuth(constants.TokenSignKeysAndCertDir,
		constants.TrustedCAsStoreDir, cfgRouter.retrieveJWTSigningCerts,
		time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	subRouter = SetRolesRoutes(subRouter, dataStore)
	subRouter = SetUsersRoutes(subRouter, dataStore)
	subRouter = SetAuthJwtTokenRoutes(subRouter, dataStore, tokenFactory)

}

func (router Router) retrieveJWTSigningCerts() error {
	//No implementation is required as AAS will already have the jwt certificate created as part of setup task
	defaultLog.Debug("Callback function to get JWT certs called")
	return nil
}
