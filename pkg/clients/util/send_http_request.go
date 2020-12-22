/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"

	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/aas"

	"github.com/pkg/errors"
)

var aasClient = aas.NewJWTClient("")
var aasRWLock = sync.RWMutex{}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func addJWTToken(req *http.Request, aasURL, serviceUsername, servicePassword string,
	trustedCaCerts []x509.Certificate) error {
	log.Trace("clients/send_http_request:addJWTToken() Entering")
	defer log.Trace("clients/send_http_request:addJWTToken() Leaving")

	var err error
	if aasClient.BaseURL == "" {
		aasClient = aas.NewJWTClient(aasURL)
		if aasClient.HTTPClient == nil {
			if len(trustedCaCerts) == 0 {
				aasClient.HTTPClient = clients.HTTPClientTLSNoVerify()
			} else {
				aasClient.HTTPClient, err = clients.HTTPClientWithCA(trustedCaCerts)
				if err != nil {
					return errors.Wrap(err, "clients/send_http_request.go:addJWTToken() Error initializing http client")
				}
			}
		}
	}
	aasRWLock.RLock()
	jwtToken, err := aasClient.GetUserToken(serviceUsername)
	secLog.Debug("clients/send_http_request:addJWTToken() Getting user token from AAS...")
	aasRWLock.RUnlock()

	if err != nil {
		aasRWLock.Lock()
		aasClient.AddUser(serviceUsername, servicePassword)
		err = aasClient.FetchAllTokens()
		if err != nil {
			return errors.Wrap(err, "clients/send_http_request.go:addJWTToken() Could not fetch token")
		}
		jwtToken, err = aasClient.GetUserToken(serviceUsername)
		if err != nil {
			return errors.Wrap(err, "clients/send_http_request.go:addJWTToken() Error retrieving token from cache")
		}
		aasRWLock.Unlock()
	}
	secLog.Debug("clients/send_http_request:addJWTToken() successfully added jwt bearer token")
	secLog.Debug("clients/send_http_request:addJWTToken() successfully added jwt bearer token ", string(jwtToken))
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

//SendRequest method is used to create an http client object and send the request to the server
func SendRequest(req *http.Request, aasURL, serviceUsername, servicePassword string,
	trustedCaCerts []x509.Certificate) ([]byte, error) {
	log.Trace("clients/send_http_request:SendRequest() Entering")
	defer log.Trace("clients/send_http_request:SendRequest() Leaving")

	var err error
	//This has to be done for dynamic loading or unloading of certificates
	if len(trustedCaCerts) == 0 {
		aasClient.HTTPClient = clients.HTTPClientTLSNoVerify()
	} else {
		aasClient.HTTPClient, err = clients.HTTPClientWithCA(trustedCaCerts)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Failed to create http client")
		}
	}
	err = addJWTToken(req, aasURL, serviceUsername, servicePassword, trustedCaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Failed to add JWT token")
	}

	log.Debug("clients/send_http_request:SendRequest() AAS client successfully created")

	response, err := aasClient.HTTPClient.Do(req)
	log.Trace("clients/send_http_request.go:SendRequest() Mahesh -> response.", response)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		aasRWLock.Lock()
		aasClient.FetchAllTokens()
		aasRWLock.Unlock()
		err = addJWTToken(req, aasURL, serviceUsername, servicePassword, trustedCaCerts)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Failed to add JWT token")
		}
		response, err = aasClient.HTTPClient.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
		}
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		return nil, errors.Wrap(errors.New("HTTP Status :"+strconv.Itoa(response.StatusCode)),
			"clients/send_http_request.go:SendRequest() Error from response")
	}

	//create byte array of HTTP response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
	}
	log.Debug("clients/send_http_request.go:SendRequest() Received the response successfully")
	return body, nil
}

//SendNoAuthRequest method is used to create an http client object and send the request to the server
func SendNoAuthRequest(req *http.Request, trustedCaCerts []x509.Certificate) ([]byte, error) {
	log.Trace("clients/send_http_request:SendNoAuthRequest() Entering")
	defer log.Trace("clients/send_http_request:SendNoAuthRequest() Leaving")

	var err error
	var client *http.Client
	//This has to be done for dynamic loading or unloading of certificates
	if len(trustedCaCerts) == 0 {
		client = clients.HTTPClientTLSNoVerify()
	} else {
		client, err = clients.HTTPClientWithCA(trustedCaCerts)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:SendNoAuthRequest() Failed to create http client")
		}
	}

	log.Debug("clients/send_http_request:SendNoAuthRequest() HTTP client successfully created")

	response, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendNoAuthRequest() Error from response")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		return nil, errors.Wrap(errors.New("HTTP Status :"+strconv.Itoa(response.StatusCode)),
			"clients/send_http_request.go:SendNoAuthRequest() Error from response")
	}

	//create byte array of HTTP response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendNoAuthRequest() Error from response")
	}
	log.Debug("clients/send_http_request.go:SendNoAuthRequest() Received the response successfully")
	return body, nil
}
