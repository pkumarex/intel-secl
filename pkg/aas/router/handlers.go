/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	consts "github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/pkg/errors"
	"net/http"

	"github.com/jinzhu/gorm"

	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

// endpointHandler which writes generic response
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

func permissionsHandler(eh endpointHandler, permissionNames []string) endpointHandler {
	defaultLog.Trace("router/handlers:permissionsHandler() Entering")
	defer defaultLog.Trace("router/handlers:permissionsHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := comctx.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, writeErr := w.Write([]byte("Could not get user permissions from http context"))
			if writeErr != nil {
				defaultLog.WithError(writeErr).Error("Failed to write response")
			}
			secLog.Errorf("router/handlers:permissionsHandler() %s Permission: %v | Context: %v", commLogMsg.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "router/handlers:permissionsHandler() Could not get user permissions from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: consts.ServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Errorf("router/handlers:permissionsHandler() %s Insufficient privileges to access %s", commLogMsg.UnauthorizedAccess, r.RequestURI)
			return &commErr.PrivilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("router/handlers:permissionsHandler() %s - %s", commLogMsg.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

// Generic handler for writing response header and body for all handler functions
func ResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error), contentType string) endpointHandler {
	defaultLog.Trace("router/handlers:ResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:ResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		if data != nil {
			_, err = w.Write([]byte(fmt.Sprintf("%v", data)))
			if err != nil {
				defaultLog.Errorf("router/handlers:ResponseHandler() Failed to write data")
			}
		}
		return nil
	}
}

func ErrorHandler(eh endpointHandler) http.HandlerFunc {
	defaultLog.Trace("router/handlers:ErrorHandler() Entering")
	defer defaultLog.Trace("router/handlers:ErrorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				defaultLog.Errorf("Panic occurred: %+v", err)
				http.Error(w, "Unknown Error", http.StatusInternalServerError)
			}
		}()
		if err := eh(w, r); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *commErr.HandledError:
				http.Error(w, t.Message, t.StatusCode)
			case *commErr.PrivilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func errorFormatter(err error, status int) error {
	defaultLog.Trace("router/handlers:errorFormatter() Entering")
	defer defaultLog.Trace("router/handlers:errorFormatter() Leaving")
	switch t := err.(type) {
	case *commErr.EndpointError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	case *commErr.ResourceError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	case *commErr.PrivilegeError:
		err = &commErr.HandledError{StatusCode: status, Message: t.Message}
	}
	return err
}

type PrivilegeError struct {
	StatusCode int
	Message    string
}

func (e PrivilegeError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type ResourceError struct {
	StatusCode int
	Message    string
}

func (e ResourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}
