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

//setKeyTransferPolicyRoutes registers routes to perform KeyTransferPolicy CRUD operations
func setKeyTransferPolicyRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/key_transfer_policy:setKeyTransferPolicyRoutes() Entering")
	defer defaultLog.Trace("router/key_transfer_policy:setKeyTransferPolicyRoutes() Leaving")

	keyStore := directory.NewKeyStore(constants.KeysDir)
	policyStore := directory.NewKeyTransferPolicyStore(constants.KeysTransferPolicyDir)
	transferPolicyController := controllers.NewKeyTransferPolicyController(policyStore, keyStore)
	keyTransferPolicyIdExpr := "/key-transfer-policies/" + validation.IdReg

	router.Handle("/key-transfer-policies",
		ErrorHandler(permissionsHandler(JsonResponseHandler(transferPolicyController.Create),
			[]string{constants.KeyTransferPolicyCreate}))).Methods("POST")

	router.Handle(keyTransferPolicyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(transferPolicyController.Retrieve),
			[]string{constants.KeyTransferPolicyRetrieve}))).Methods("GET")

	router.Handle(keyTransferPolicyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(transferPolicyController.Delete),
			[]string{constants.KeyTransferPolicyDelete}))).Methods("DELETE")

	router.Handle("/key-transfer-policies",
		ErrorHandler(permissionsHandler(JsonResponseHandler(transferPolicyController.Search),
			[]string{constants.KeyTransferPolicySearch}))).Methods("GET")

	return router
}
