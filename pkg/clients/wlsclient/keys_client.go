/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wlsclient

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/util"
	wlsModel "github.com/intel-secl/intel-secl/v3/pkg/model/wls"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"path"
)

type KeysClient interface {
	GetKeyWithURL(keyUrl string, hardwareUUID string) (wlsModel.ReturnKey, error)
}

type keysClientImpl struct {
	caCerts []x509.Certificate
	cfg     *wlsClientConfig
}

// GetKeyWithURL method is used to get the image flavor-key from the workload service
func (client keysClientImpl) GetKeyWithURL(keyUrl string, hardwareUUID string) (wlsModel.ReturnKey, error) {
	log.Trace("wlsclient/keys_client:GetKeyWithURL() Entering")
	defer log.Trace("wlsclient/keys_client:GetKeyWithURL() Leaving")

	var retKey wlsModel.ReturnKey

	requestURL, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return retKey, errors.New("wlsclient/keys_client:GetKeyWithURL() error retrieving WLS API URL")
	}

	requestURL.Path = path.Join(requestURL.Path, "keys")

	var rBody = wlsModel.RequestKey{
		HwId:   hardwareUUID,
		KeyUrl: keyUrl,
	}
	jbody, err := json.Marshal(rBody)

	httpRequest, err := http.NewRequest("POST", requestURL.String(), bytes.NewBuffer([]byte(jbody)))
	if err != nil {
		return retKey, err
	}

	log.Debugf("wlsclient/keys_client:GetKeyWithURL() WLS key retrieval GET request URL: %s", requestURL.String())
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := util.SendRequest(httpRequest, client.cfg.AasApiURL, client.cfg.Username, client.cfg.Password, client.caCerts)
	if err != nil {
		return retKey, errors.Wrap(err, "wlsclient/keys_client:GetKeyWithURL() Error while getting response from Key from WLS API")
	}

	if httpResponse != nil {
		//deserialize the response to ReturnKey response
		err = json.Unmarshal(httpResponse, &retKey)
		if err != nil {
			return retKey, errors.Wrap(err, "wlsclient/keys_client:GetKeyWithURL() Failed to unmarshal response into key info")
		}
	}
	log.Debug("wlsclient/keys_client:GetKeyWithURL() Successfully retrieved Key")
	return retKey, nil
}
