/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wlsclient

import (
	"crypto/x509"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/util"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	wlsModel "github.com/intel-secl/intel-secl/v3/pkg/model/wls"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"path"
)

type FlavorsClient interface {
	GetImageFlavorKey(imageUUID, hardwareUUID string) (wlsModel.FlavorKey, error)
	GetImageFlavor(imageID, flavorPart string) (wlsModel.SignedImageFlavor, error)
}

type flavorsClientImpl struct {
	caCerts []x509.Certificate
	cfg     *wlsClientConfig
}

var log = commLog.GetDefaultLogger()

// GetImageFlavorKey method is used to get the image flavor-key from the workload service
func (client flavorsClientImpl) GetImageFlavorKey(imageUUID, hardwareUUID string) (wlsModel.FlavorKey, error) {
	log.Trace("wlsclient/flavors_client:GetImageFlavorKey() Entering")
	defer log.Trace("wlsclient/flavors_client:GetImageFlavorKey() Leaving")

	var flavorKeyInfo wlsModel.FlavorKey
	requestURL, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return flavorKeyInfo, errors.New("wlsclient/flavors_client:GetImageFlavorKey() error retrieving WLS API URL")
	}
	requestURL.Path = path.Join(requestURL.Path, "images/"+imageUUID+"/flavor-key")
	parameters := url.Values{}
	parameters.Add("hardware_uuid", hardwareUUID)
	requestURL.RawQuery = parameters.Encode()

	httpRequest, err := http.NewRequest("GET", requestURL.String(), nil)
	if err != nil {
		return flavorKeyInfo, err
	}

	log.Debugf("wlsclient/flavors_client:GetImageFlavorKey() WLS image-flavor-key retrieval GET request URL: %s", requestURL.String())
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := util.SendRequest(httpRequest, client.cfg.AasApiURL, client.cfg.Username, client.cfg.Password, client.caCerts)
	if err != nil {
		return flavorKeyInfo, errors.Wrap(err, "wlsclient/flavors_client:GetImageFlavorKey() Error while getting response from Get Image Flavor-Key from WLS API")
	}

	if httpResponse != nil {
		//deserialize the response to flavorKeyInfo response
		err = json.Unmarshal(httpResponse, &flavorKeyInfo)
		if err != nil {
			return flavorKeyInfo, errors.Wrap(err, "wlsclient/flavors_client:GetImageFlavorKey() Failed to unmarshal response into flavor key info")
		}
	}
	log.Debug("wlsclient/flavors_client:GetImageFlavorKey() Successfully retrieved Flavor-Key")
	return flavorKeyInfo, nil
}

// GetImageFlavor method is used to get the image flavor from the workload service
func (client flavorsClientImpl) GetImageFlavor(imageID, flavorPart string) (wlsModel.SignedImageFlavor, error) {
	log.Trace("wlsclient/flavors_client:GetImageFlavor() Entering")
	defer log.Trace("wlsclient/flavors_client:GetImageFlavor() Leaving")

	var flavor wlsModel.SignedImageFlavor

	requestURL, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return flavor, errors.New("wlsclient/flavors_client:GetImageFlavor() error retrieving WLS API URL")
	}

	requestURL.Path = path.Join(requestURL.Path, "images/"+imageID+"/flavors")
	parameters := url.Values{}
	parameters.Add("flavor_part", flavorPart)
	requestURL.RawQuery = parameters.Encode()

	httpRequest, err := http.NewRequest("GET", requestURL.String(), nil)
	if err != nil {
		return flavor, err
	}

	log.Debugf("wlsclient/flavors_client:GetImageFlavor() WLS image-flavor retrieval GET request URL: %s", requestURL.String())
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := util.SendRequest(httpRequest, client.cfg.AasApiURL, client.cfg.Username, client.cfg.Password, client.caCerts)
	if err != nil {
		return flavor, errors.Wrap(err, "wlsclient/flavors_client:GetImageFlavor() Error in response from WLS GetImageFlavor API")
	}

	if httpResponse != nil {
		// deserialize the response to ImageFlavor response
		err = json.Unmarshal(httpResponse, &flavor)
		if err != nil {
			return flavor, errors.Wrap(err, "wlsclient/flavors_client:GetImageFlavor() Failed to unmarshal response into flavor")
		}
	}
	log.Debugf("wlsclient/flavors_client:GetImageFlavor() response from API: %s", string(httpResponse))

	return flavor, nil
}
