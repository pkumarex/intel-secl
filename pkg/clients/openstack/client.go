/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package openstack

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

//Authorization Authorization Details for Openstack
type Authorization struct {
	Auth struct {
		Identity struct {
			Methods  []string `json:"methods"`
			Password struct {
				User struct {
					Name   string `json:"name"`
					Domain struct {
						Name string `json:"name"`
					} `json:"domain"`
					Password string `json:"password"`
				} `json:"user"`
			} `json:"password"`
		} `json:"identity"`
		Scope struct {
			Project struct {
				Name   string `json:"name"`
				Domain struct {
					Name string `json:"name"`
				} `json:"domain"`
			} `json:"project"`
		} `json:"scope"`
	} `json:"auth"`
}

//OpenStack interface for creating new Openstack client,getting response from client
type OpenStack interface {
	NewOpenstackClient(url string, token string, certPath string) (*Client, error)
	SendRequest(reqParams *RequestParams) (*http.Response, error)
}

//Client Details for Openstack client
type Client struct {
	AuthURL    *url.URL
	ApiURL     *url.URL
	UserName   string
	Password   string
	Token      string
	HTTPClient *http.Client
	// Path to the Openstack Server TLS Cert
	CertPath string
}

//RequestParams for passing request parameters while making API calls
type RequestParams struct {
	Method            string
	URL               *url.URL
	Body              io.Reader
	AdditionalHeaders map[string]string
}

//NewOpenstackClient Creates new client for Openstack
func NewOpenstackClient(authRL *url.URL, apiURL *url.URL, userName string, password string, certPath string) (*Client, error) {
	log.Trace("openstack/client:NewOpenstackClient() Entering")
	defer log.Trace("openstack/client:NewOpenstackClient() Leaving")

	openstackClient := Client{
		AuthURL:  authRL,
		ApiURL:   apiURL,
		UserName: userName,
		Password: password,
		CertPath: certPath,
	}

	err := openstackClient.validateOpenstackDetails()
	if err != nil {
		return nil, errors.Wrap(err, "openstack/client:NewOpenstackClient() Invalid Openstack details provided")
	}

	osClient, err := openstackClient.getOpenstackHTTPClient()
	if err != nil {
		return nil, errors.Wrap(err, "openstack/client:NewOpenstackClient() Error in Creating Client")
	}

	openstackClient.HTTPClient = osClient

	err = openstackClient.updateOpenstackToken()
	if err != nil {
		return nil, errors.Wrap(err, "openstack/client:NewOpenstackClient() Error in updating openstack Token")
	}

	return &openstackClient, nil
}

func (openstackClient *Client) validateOpenstackDetails() error {
	log.Trace("openstack/client:validateOpenstackDetails() Entering")
	defer log.Trace("openstack/client:validateOpenstackDetails() Leaving")

	protocols := make(map[string]byte)
	protocols["http"] = 0
	protocols["https"] = 0

	// check for url nilness
	if openstackClient.ApiURL == nil {
		return errors.New("openstack/client:validateOpenstackDetails() Openstack API URL is nil")
	}
	if openstackClient.AuthURL == nil {
		return errors.New("openstack/client:validateOpenstackDetails() Openstack Auth URL is nil")
	}

	err := validation.ValidateURL(openstackClient.AuthURL.String(), protocols, "/v3/auth/tokens")
	if err != nil {
		return errors.Wrap(err, "openstack/client:validateOpenstackDetails() Openstack Auth URL is Not Valid")
	}

	err = validation.ValidateAccount(openstackClient.UserName, openstackClient.Password)
	if err != nil {
		return errors.Wrap(err, "openstack/client:validateOpenstackDetails() Openstack UserName or Password is Invalid")
	}

	if openstackClient.CertPath != "" {
		if _, err := os.Stat(openstackClient.CertPath); err != nil {
			return errors.Wrap(err, "openstack/client:validateOpenstackDetails() Openstack TLS cert file cannot be read")
		}
	}

	return nil
}

//updateOpenstackToken Update the Openstack token
func (openstackClient *Client) updateOpenstackToken() error {
	log.Trace("openstack/client:updateOpenstackToken() Entering")
	defer log.Trace("openstack/client:updateOpenstackToken() Leaving")

	authURL := openstackClient.AuthURL
	method := "POST"
	domain := "default"

	authorization := Authorization{
		Auth: struct {
			Identity struct {
				Methods  []string "json:\"methods\""
				Password struct {
					User struct {
						Name   string "json:\"name\""
						Domain struct {
							Name string "json:\"name\""
						} "json:\"domain\""
						Password string "json:\"password\""
					} "json:\"user\""
				} "json:\"password\""
			} "json:\"identity\""
			Scope struct {
				Project struct {
					Name   string "json:\"name\""
					Domain struct {
						Name string "json:\"name\""
					} "json:\"domain\""
				} "json:\"project\""
			} "json:\"scope\""
		}{
			Identity: struct {
				Methods  []string "json:\"methods\""
				Password struct {
					User struct {
						Name   string "json:\"name\""
						Domain struct {
							Name string "json:\"name\""
						} "json:\"domain\""
						Password string "json:\"password\""
					} "json:\"user\""
				} "json:\"password\""
			}{
				Methods: []string{openstackClient.Password},
				Password: struct {
					User struct {
						Name   string "json:\"name\""
						Domain struct {
							Name string "json:\"name\""
						} "json:\"domain\""
						Password string "json:\"password\""
					} "json:\"user\""
				}{
					User: struct {
						Name   string "json:\"name\""
						Domain struct {
							Name string "json:\"name\""
						} "json:\"domain\""
						Password string "json:\"password\""
					}{
						Name: openstackClient.UserName,
						Domain: struct {
							Name string "json:\"name\""
						}{
							Name: domain,
						},
						Password: openstackClient.Password,
					},
				},
			},
			Scope: struct {
				Project struct {
					Name   string "json:\"name\""
					Domain struct {
						Name string "json:\"name\""
					} "json:\"domain\""
				} "json:\"project\""
			}{
				Project: struct {
					Name   string "json:\"name\""
					Domain struct {
						Name string "json:\"name\""
					} "json:\"domain\""
				}{
					Name: openstackClient.UserName,
					Domain: struct {
						Name string "json:\"name\""
					}{
						Name: domain,
					},
				},
			},
		},
	}

	jsonValue, err := json.Marshal(authorization)
	if err != nil {
		return errors.Wrap(err, "openstack/client:updateOpenstackToken() Error in marshalling the authorization data")
	}

	payload := bytes.NewReader(jsonValue)

	req, err := http.NewRequest(method, authURL.String(), payload)

	if err != nil {
		return errors.Wrap(err, "openstack/client:updateOpenstackToken() Error in creating new request")
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := openstackClient.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "openstack/client:updateOpenstackToken() Error in retrieving the Openstack token")
	}
	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	log.Debug("openstack/client:updateOpenstackToken() The HTTPClient response is received successfully ")
	token := res.Header.Get("X-Subject-Token")
	if token == "" {
		return errors.New("openstack/client:updateOpenstackToken() Error in retrieving the token")
	}
	log.Debug("openstack/client:updateOpenstackToken() The Token is received successfully ")
	openstackClient.Token = token

	return nil
}

//SendRequest API for sending Requests to openstack
func (openstackClient *Client) SendRequest(reqParams *RequestParams) (*http.Response, error) {
	log.Trace("openstack/client:SendRequest() Entering")
	defer log.Trace("openstack/client:SendRequest() Leaving")

	if openstackClient == nil || openstackClient.HTTPClient == nil {
		return nil, errors.New("openstack/client:SendRequest() Openstack Client is not initialized")
	}

	err := openstackClient.validateOpenstackDetails()
	if err != nil {
		return nil, errors.Wrap(err, "openstack/client:SendRequest() Openstack Client has invalid values")
	}

	request, err := http.NewRequest(reqParams.Method, reqParams.URL.String(), reqParams.Body)
	if err != nil {
		return nil, errors.Wrap(err, "openstack/client:SendRequest() Error in creating the new request")
	}

	request.Header.Add("OpenStack-API-Version", constants.OpenStackAPIVersion)
	request.Header.Set("x-auth-token", openstackClient.Token)

	if len(reqParams.AdditionalHeaders) > 0 {

		for key, value := range reqParams.AdditionalHeaders {
			request.Header.Add(key, value)
		}
	}
	res, err := openstackClient.HTTPClient.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, "openstack/client:SendRequest() Error in receiving response")
	}

	if res.StatusCode == http.StatusUnauthorized {
		err := openstackClient.updateOpenstackToken()
		if err != nil {
			return nil, errors.Wrap(err, "openstack/client:SendRequest() Error in fetching Token for Openstack")
		}
		request.Header.Set("x-auth-token", openstackClient.Token)

		res, err = openstackClient.HTTPClient.Do(request)
		if err != nil {
			return nil, errors.Wrap(err, "openstack/client:SendRequest() Error in receiving response")
		}
	}

	return res, err
}

func (openstackClient *Client) getOpenstackHTTPClient() (*http.Client, error) {
	log.Trace("openstack/client:getOpenstackHTTPClient() Entering")
	defer log.Trace("openstack/client:getOpenstackHTTPClient() Leaving")

	if openstackClient.HTTPClient != nil {
		return openstackClient.HTTPClient, nil
	}

	var osClient *http.Client

	if openstackClient.CertPath != "" {
		var certArray []x509.Certificate

		x509Certificate, err := crypt.GetCertFromPemFile(openstackClient.CertPath)
		if err != nil {
			return nil, errors.Wrap(err, "openstack/client:getOpenstackHTTPClient() Unable to Read X509 Certificate")
		}
		certArray = append(certArray, *x509Certificate)

		newTLSClient, err := clients.HTTPClientWithCA(certArray)
		if err != nil {
			return nil, errors.Wrap(err, "openstack/client:getOpenstackHTTPClient() Error in creating client with certPath "+openstackClient.CertPath)
		}
		osClient = newTLSClient
	} else {
		//we need a TLS no verify while running setup tasks because certs not exchanged at this point of time.
		log.Debug("openstack/client:getOpenstackHTTPClient() Creating Insecure K8s Client")
		osClient = clients.HTTPClientTLSNoVerify()
	}

	return osClient, nil
}
