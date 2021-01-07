/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/domain"
)

func SetUsersRoutes(r *mux.Router, db domain.AASDatabase) *mux.Router {
	defaultLog.Trace("router/users:SetUsersRoutes() Entering")
	defer defaultLog.Trace("router/users:SetUsersRoutes() Leaving")

	controller := controllers.UsersController{Database: db}

	r.Handle("/users", ErrorHandler(permissionsHandler(ResponseHandler(controller.CreateUser,
		"application/json"), []string{consts.UserCreate}))).Methods("POST")
	r.Handle("/users", ErrorHandler(permissionsHandler(ResponseHandler(controller.QueryUsers,
		"application/json"), []string{consts.UserSearch}))).Methods("GET")
	r.Handle("/users/{id}", ErrorHandler(permissionsHandler(ResponseHandler(controller.DeleteUser,
		""), []string{consts.UserDelete}))).Methods("DELETE")
	r.Handle("/users/{id}", ErrorHandler(permissionsHandler(ResponseHandler(controller.GetUser,
		"application/json"), []string{consts.UserRetrieve}))).Methods("GET")
	r.Handle("/users/{id}", ErrorHandler(permissionsHandler(ResponseHandler(controller.UpdateUser,
		"application/json"), []string{consts.UserStore}))).Methods("PATCH")
	r.Handle("/users/{id}/roles", ErrorHandler(ResponseHandler(controller.AddUserRoles,
		"application/json"))).Methods("POST")
	r.Handle("/users/{id}/roles", ErrorHandler(ResponseHandler(controller.QueryUserRoles,
		"application/json"))).Methods("GET")
	r.Handle("/users/{id}/permissions", ErrorHandler(ResponseHandler(controller.QueryUserPermissions,
		"application/json"))).Methods("GET")
	r.Handle("/users/{id}/roles/{role_id}", ErrorHandler(permissionsHandler(ResponseHandler(controller.GetUserRoleById,
		"application/json"), []string{consts.UserRoleRetrieve}))).Methods("GET")
	r.Handle("/users/{id}/roles/{role_id}", ErrorHandler(permissionsHandler(ResponseHandler(controller.DeleteUserRole,
		""), []string{consts.UserRoleDelete}))).Methods("DELETE")

	return r
}

func SetUsersNoAuthRoutes(r *mux.Router, db domain.AASDatabase) *mux.Router {
	defaultLog.Trace("router/users:SetUsersNoAuthRoutes() Entering")
	defer defaultLog.Trace("router/users:SetUsersNoAuthRoutes() Leaving")

	controller := controllers.UsersController{Database: db}
	r.Handle("/users/changepassword", ErrorHandler(ResponseHandler(controller.ChangePassword,
		""))).Methods("PATCH")

	return r
}
