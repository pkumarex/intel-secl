/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"

	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	aasClient "github.com/intel-secl/intel-secl/v3/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	consts "github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/pkg/errors"
)

// endpointHandler which writes generic response
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

type privilegeError struct {
	StatusCode int
	Message    string
}

func (err privilegeError) Error() string {
	return fmt.Sprintf("Status code %d, message %s", err.StatusCode, err.Message)
}

// Generic handler for writing response header and body for all handler functions
func ResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) endpointHandler {
	defaultLog.Trace("router/handlers:ResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:ResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		w.WriteHeader(status)
		if data != nil {
			_, err = w.Write(data.([]byte))
			if err != nil {
				log.WithError(err).Errorf("Unable to write response")
			}
		}
		return nil
	}
}

// JsonResponseHandler  is the same as http.JsonResponseHandler, but returns an error that can be handled by a generic
//// middleware handler
func JsonResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) endpointHandler {
	defaultLog.Trace("router/handlers:JsonResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:JsonResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get("Accept") != constants.HTTPMediaTypeJson {
			return errorFormatter(&commErr.EndpointError{
				Message: "Invalid Accept type",
			}, http.StatusUnsupportedMediaType)
		}

		data, status, err := h(w, r) // execute application handler
		if err != nil {
			return errorFormatter(err, status)
		}
		w.Header().Set("Content-Type", constants.HTTPMediaTypeJson)
		w.WriteHeader(status)
		if data != nil {
			// Send JSON response back to the client application
			err = json.NewEncoder(w).Encode(data)
			if err != nil {
				defaultLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
				secLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			}
		}
		return nil
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

func permissionsHandler(eh endpointHandler, permissionNames []string) endpointHandler {
	defaultLog.Trace("router/handlers:permissionsHandler() Entering")
	defer defaultLog.Trace("router/handlers:permissionsHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := comctx.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			secLog.WithError(err).Errorf("router/handlers:permissionsHandler() %s Permission: %v | Context: %v", commLogMsg.AuthenticationFailed, permissionNames, r.Context())
			_, writeErr := w.Write([]byte("Could not get user permissions from http context"))
			if writeErr != nil {
				log.WithError(writeErr).Error("Error writing data")
			}
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

func permissionsHandlerUsingTLSMAuth(eh endpointHandler, aasAPIUrl string, kbsConfig config.KBSConfig) endpointHandler {
	defaultLog.Trace("router/handlers:permissionsHandlerUsingTLSMAuth() Entering")
	defer defaultLog.Trace("router/handlers:permissionsHandlerUsingTLSMAuth() Leaving")

	return func(responseWriter http.ResponseWriter, request *http.Request) error {
		//Get trusted CA certs from the directory
		caCerts, err := crypt.GetCertsFromDir(consts.TrustedCaCertsDir)
		if err != nil {
			defaultLog.WithError(err).Errorf("router/handlers:permissionsHandlerUsingTLSMAuth() Error while getting certs from %s", consts.TrustedCaCertsDir)
			return err
		}

		var intermediateCerts []x509.Certificate
		for _, certificates := range request.TLS.PeerCertificates[1:] {
			intermediateCerts = append(intermediateCerts, *certificates)
		}

		verifyRootCAOpts := x509.VerifyOptions{
			Roots:         crypt.GetCertPool(caCerts),
			Intermediates: crypt.GetCertPool(intermediateCerts),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		if _, err := request.TLS.PeerCertificates[0].Verify(verifyRootCAOpts); err != nil {
			secLog.WithError(err).Error("router/handlers:permissionsHandlerUsingTLSMAuth() Error verifying certificate chain for TLS certificate. No " +
				"valid certificate chain could be found")
			return errors.New("Error verifying certificate chain for TLS certificate. No " +
				"valid certificate chain could be found")
		}

		secLog.Debug("router/handlers:permissionsHandlerUsingTLSMAuth() TLS certificate chain verification successful")

		client, err := clients.HTTPClientWithCA(caCerts)

		jwtcl := aasClient.NewJWTClient(aasAPIUrl)
		jwtcl.HTTPClient = client
		jwtcl.AddUser(kbsConfig.UserName, kbsConfig.Password)
		tokenBytes, err := jwtcl.FetchTokenForUser(kbsConfig.UserName)
		if err != nil {
			secLog.WithError(err).Error("router/handlers:permissionsHandlerUsingTLSMAuth() Could not fetch token for user " + kbsConfig.UserName)
			return errors.New("Could not fetch token for user " + kbsConfig.UserName)
		}

		aasClient := aasClient.Client{
			BaseURL:    aasAPIUrl,
			JWTToken:   tokenBytes,
			HTTPClient: client,
		}
		userDetails, err := aasClient.GetUsers(request.TLS.PeerCertificates[0].Subject.CommonName)
		if err != nil {
			defaultLog.WithError(err).Errorf("router/handlers:permissionsHandlerUsingTLSMAuth() Error while getting user details from AAS")
			return errors.New("Error while getting user details from AAS")
		}

		userRoles, err := aasClient.GetRolesForUser(userDetails[0].ID)
		if err != nil {
			defaultLog.WithError(err).Errorf("router/handlers:permissionsHandlerUsingTLSMAuth() Error while getting permission details from AAS")
			return errors.New("Error while getting permission details from AAS")
		}

		roleFound := false
		for _, roles := range userRoles {
			if roles.Service == consts.ServiceName && roles.Name == consts.TransferRoleType {
				roleFound = true
				break
			}
		}

		if !roleFound {
			responseWriter.WriteHeader(http.StatusUnauthorized)
			secLog.Errorf("router/handlers:permissionsHandlerUsingTLSMAuth() %s Insufficient privileges to access %s", commLogMsg.UnauthorizedAccess, request.RequestURI)
			return &privilegeError{Message: "Insufficient privileges to access " + request.RequestURI, StatusCode: http.StatusUnauthorized}
		}

		secLog.Infof("router/handlers:permissionsHandlerUsingTLSMAuth() %s - %s", commLogMsg.AuthorizedAccess, request.RequestURI)
		return eh(responseWriter, request)
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
