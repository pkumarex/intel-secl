/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wlsclient

import "github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"

type WLSClientFactory interface {
	FlavorsClient() (FlavorsClient, error)
	ReportsClient() (ReportsClient, error)
	KeysClient() (KeysClient, error)
}

type wlsClientConfig struct {
	// BaseURL specifies the URL base for the WLS
	BaseURL string

	AasApiURL string
	// BearerToken is the JWT token required for authentication with external services
	BearerToken string
	// CaCerts is required for HTTP Client
	CaCerts string

	Username string

	Password string
}

func NewWLSClientFactory(baseURL, AasApiURL, username, password, caCertsDir string) (WLSClientFactory, error) {

	cfg := wlsClientConfig{BaseURL: baseURL, AasApiURL: AasApiURL, Username: username, Password: password, CaCerts: caCertsDir}

	defaultFactory := defaultWLSClientFactory{&cfg}
	return &defaultFactory, nil
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type defaultWLSClientFactory struct {
	cfg *wlsClientConfig
}

func (wlsClientFactory *defaultWLSClientFactory) FlavorsClient() (FlavorsClient, error) {
	caCerts, err := crypt.GetCertsFromDir(wlsClientFactory.cfg.CaCerts)
	if err != nil {
		return nil, err
	}
	return &flavorsClientImpl{caCerts, wlsClientFactory.cfg}, nil
}

func (wlsClientFactory *defaultWLSClientFactory) ReportsClient() (ReportsClient, error) {
	caCerts, err := crypt.GetCertsFromDir(wlsClientFactory.cfg.CaCerts)
	if err != nil {
		return nil, err
	}
	return &reportsClientImpl{caCerts, wlsClientFactory.cfg}, nil
}

func (wlsClientFactory *defaultWLSClientFactory) KeysClient() (KeysClient, error) {
	caCerts, err := crypt.GetCertsFromDir(wlsClientFactory.cfg.CaCerts)
	if err != nil {
		return nil, err
	}
	return &keysClientImpl{caCerts, wlsClientFactory.cfg}, nil
}
