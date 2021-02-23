/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package host_connector

import (
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/ta"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"net/url"
	"testing"
)

func TestGetHostDetails(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	assert.NoError(t, err)
	var hostInfo taModel.HostInfo
	hostInfoJson, err := ioutil.ReadFile("./test/sample_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(hostInfoJson, &hostInfo)
	assert.NoError(t, err)

	mockTAClient.On("GetHostInfo").Return(hostInfo, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	hostInfo, err = intelConnector.GetHostDetails()
	assert.NoError(t, err)
	assert.Equal(t, "RedHatEnterprise", hostInfo.OSName)
	assert.Equal(t, "Intel Corporation", hostInfo.BiosName)
}

func TestCreateHostManifestFromSampleData(t *testing.T) {

	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()

	// read sample tpm quote that will be returned by the mock client
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("./test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)
	mockTAClient.On("GetTPMQuote", mock.Anything, mock.Anything, mock.Anything).Return(tpmQuoteResponse, nil)

	// read sample platform-info that will be returned my the mock client
	var hostInfo taModel.HostInfo
	b, err = ioutil.ReadFile("./test/sample_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(b, &hostInfo)
	assert.NoError(t, err)
	mockTAClient.On("GetHostInfo").Return(hostInfo, nil)

	// read the aik that will be returned by the mock
	aikBytes, err := ioutil.ReadFile("./test/aik.pem")
	aikDer, _ := pem.Decode(aikBytes)
	assert.NoError(t, err)
	mockTAClient.On("GetAIK").Return(aikDer.Bytes, nil)

	// the sample data in ./test was collected from 168.63 -- this is needed
	// for the nonce to verify...
	baseUrl, err := url.Parse("http://127.0.0.1:1443/")
	assert.NoError(t, err)
	mockTAClient.On("GetBaseURL").Return(baseUrl, nil)

	// binding key is only applicable to workload-agent (skip for now)
	mockTAClient.On("GetBindingKeyCertificate").Return([]byte{}, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	// the sample data in ./test used this nonce which needs to be provided to GetHostManifest...
	nonce := "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k="

	hostManifest, err := intelConnector.GetHostManifestAcceptNonce(nonce, nil)
	assert.NoError(t, err)

	json, err := json.Marshal(hostManifest)
	assert.NoError(t, err)
	t.Log(string(json))
}

func TestEventReplay256(t *testing.T) {
	// this data was extracted from an existing host manifest...
	eventLogJson := `
	{
		"pcr_index": "pcr_18",
		"event_log": [
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
				"label": "SINIT_PUBKEY_HASH",
				"info": {
					"ComponentName": "SINIT_PUBKEY_HASH",
					"EventName": "OpenSource.EventName"
				}
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
				"label": "CPU_SCRTM_STAT",
				"info": {
					"ComponentName": "CPU_SCRTM_STAT",
					"EventName": "OpenSource.EventName"
				}
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
				"label": "OSSINITDATA_CAP_HASH",
				"info": {
					"ComponentName": "OSSINITDATA_CAP_HASH",
					"EventName": "OpenSource.EventName"
				}
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
				"label": "LCP_CONTROL_HASH",
				"info": {
					"ComponentName": "LCP_CONTROL_HASH",
					"EventName": "OpenSource.EventName"
				}
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
				"label": "LCP_AUTHORITIES_HASH",
				"info": {
					"ComponentName": "LCP_AUTHORITIES_HASH",
					"EventName": "OpenSource.EventName"
				}
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
				"label": "NV_INFO_HASH",
				"info": {
					"ComponentName": "NV_INFO_HASH",
					"EventName": "OpenSource.EventName"
				}
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
				"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
				"label": "tb_policy",
				"info": {
					"ComponentName": "tb_policy",
					"EventName": "OpenSource.EventName"
				}
			}
		],
		"pcr_bank": "SHA256"
	}`

	pcr18json := `
	{
		"index": "pcr_18",
		"value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
		"pcr_bank": "SHA256"
	}`

	var eventLogEntry types.EventLogEntry
	var pcr18 types.Pcr

	assert.NoError(t, json.Unmarshal([]byte(eventLogJson), &eventLogEntry))
	assert.NoError(t, json.Unmarshal([]byte(pcr18json), &pcr18))

	cumulativeHash, err := eventLogEntry.Replay()
	assert.NoError(t, err)
	assert.Equal(t, pcr18.Value, cumulativeHash)
}

func TestGetMeasurementFromManifest(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	var manifest taModel.Manifest
	var measurement taModel.Measurement

	manifestXml, err := ioutil.ReadFile("./test/sample_manifest.xml")
	assert.NoError(t, err)

	err = xml.Unmarshal([]byte(manifestXml), &manifest)
	assert.NoError(t, err)

	measurementXml, err := ioutil.ReadFile("./test/sample_measurement.xml")
	err = xml.Unmarshal(measurementXml, &measurement)
	assert.NoError(t, err)
	mockTAClient.On("GetMeasurementFromManifest", manifest).Return(measurement, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	measurementResponse, err := intelConnector.GetMeasurementFromManifest(manifest)
	assert.NoError(t, err)
	log.Info("Measurement is : ", measurementResponse)
}

func TestDeployAssetTag(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	assert.NoError(t, err)

	hardwareUUID := "7a569dad-2d82-49e4-9156-069b0065b262"
	tag := "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k="

	mockTAClient.On("DeployAssetTag", hardwareUUID, tag).Return(nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	err = intelConnector.DeployAssetTag(hardwareUUID, tag)
	assert.NoError(t, err)
}

func TestDeploySoftwareManifest(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	assert.NoError(t, err)

	var manifest taModel.Manifest

	manifestXml, err := ioutil.ReadFile("./test/sample_manifest.xml")
	assert.NoError(t, err)

	err = xml.Unmarshal(manifestXml, &manifest)
	assert.NoError(t, err)

	mockTAClient.On("DeploySoftwareManifest", manifest).Return(nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	err = intelConnector.DeploySoftwareManifest(manifest)
	assert.NoError(t, err)
}
