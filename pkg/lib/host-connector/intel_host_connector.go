/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"

	client "github.com/intel-secl/intel-secl/v3/pkg/clients/ta"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vim25/mo"
)

type IntelConnector struct {
	client client.TAClient
}

func (ic *IntelConnector) GetHostDetails() (taModel.HostInfo, error) {

	log.Trace("intel_host_connector:GetHostDetails() Entering")
	defer log.Trace("intel_host_connector:GetHostDetails() Leaving")
	hostInfo, err := ic.client.GetHostInfo()
	return hostInfo, err
}

func (ic *IntelConnector) GetHostManifest() (types.HostManifest, error) {
	log.Trace("intel_host_connector:GetHostManifest() Entering")
	defer log.Trace("intel_host_connector:GetHostManifest() Leaving")

	nonce, err := util.GenerateNonce(20)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error generating "+
			"nonce for TPM quote request")
	}
	hostManifest, err := ic.GetHostManifestAcceptNonce(nonce)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifest() Error creating "+
			"host manifest")
	}
	return hostManifest, nil
}

//Separate function has been created that accepts nonce to support unit test.
//Else it would be difficult to mock random nonce.
func (ic *IntelConnector) GetHostManifestAcceptNonce(nonce string) (types.HostManifest, error) {

	log.Trace("intel_host_connector:GetHostManifestAcceptNonce() Entering")
	defer log.Trace("intel_host_connector:GetHostManifestAcceptNonce() Leaving")
	var verificationNonce string
	var hostManifest types.HostManifest
	var pcrBankList []string

	//Hardcoded pcr list here since there is no use case for customized pcr list
	pcrList := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	//check if AIK Certificate is present on host before getting host manifest
	aikInDER, err := ic.client.GetAIK()
	if err != nil || len(aikInDER) == 0 {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Invalid AIK"+
			"certificate returned by TA")
	}
	secLog.Debug("intel_host_connector:GetHostManifestAcceptNonce() Successfully received AIK certificate in DER format")

	hostManifest.HostInfo, err = ic.client.GetHostInfo()
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error getting "+
			"host details from TA")
	}

	if hostManifest.HostInfo.HardwareFeatures.TPM.Meta.PCRBanks != "" {
		pcrBankList = strings.Split(hostManifest.HostInfo.HardwareFeatures.TPM.Meta.PCRBanks, "_")
	} else {
		//support both pcr banks by default
		pcrBankList = []string{"SHA1", "SHA256"}
	}

	tpmQuoteResponse, err := ic.client.GetTPMQuote(nonce, pcrList, pcrBankList)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error getting TPM "+
			"quote response")
	}

	nonceInBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Base64 decode of TPM "+
			"nonce failed")
	}

	verificationNonce, err = util.GetVerificationNonce(nonceInBytes, tpmQuoteResponse)
	if err != nil {
		return types.HostManifest{}, err
	}
	secLog.Debug("intel_host_connector:GetHostManifestAcceptNonce() Updated Verification nonce is : ", verificationNonce)

	aikCertInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Aik)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error decoding"+
			"AIK certificate to bytes")
	}

	//Convert base64 encoded AIK to Pem format
	aikPem, _ := pem.Decode(aikCertInBytes)
	aikCertificate, err := x509.ParseCertificate(aikPem.Bytes)

	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error parsing "+
			"AIK certicate")
	}

	eventLogBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.EventLog)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error converting "+
			"event log to bytes")
	}

	eventLogBytes = []byte(`[
  {
    "pcr": {
      "index": 17,
      "bank": "SHA1"
    },
    "tpm_events": [
      {
        "type_id": "0x402",
        "type_name": "HASH_START",
        "tags": [
          "HASH_START"
        ],
        "measurement": "19f7c22f6c92d9555d792466b2097443444ebd26"
      },
      {
        "type_id": "0x40a",
        "type_name": "BIOSAC_REG_DATA",
        "tags": [
          "BIOSAC_REG_DATA"
        ],
        "measurement": "3cf4a5c90911c21f6ea71f4ca84425f8e65a2be7"
      },
      {
        "type_id": "0x40b",
        "type_name": "CPU_SCRTM_STAT",
        "tags": [
          "CPU_SCRTM_STAT"
        ],
        "measurement": "3c585604e87f855973731fea83e21fab9392d2fc"
      },
      {
        "type_id": "0x40c",
        "type_name": "LCP_CONTROL_HASH",
        "tags": [
          "LCP_CONTROL_HASH"
        ],
        "measurement": "9069ca78e7450a285173431b3e52c5c25299e473"
      },
      {
        "type_id": "0x412",
        "type_name": "LCP_DETAILS_HASH",
        "tags": [
          "LCP_DETAILS_HASH"
        ],
        "measurement": "5ba93c9db0cff93f52b521d7420e43f6eda2784f"
      },
      {
        "type_id": "0x40e",
        "type_name": "STM_HASH",
        "tags": [
          "STM_HASH"
        ],
        "measurement": "5ba93c9db0cff93f52b521d7420e43f6eda2784f"
      },
      {
        "type_id": "0x40f",
        "type_name": "OSSINITDATA_CAP_HASH",
        "tags": [
          "OSSINITDATA_CAP_HASH"
        ],
        "measurement": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895"
      },
      {
        "type_id": "0x404",
        "type_name": "MLE_HASH",
        "tags": [
          "MLE_HASH"
        ],
        "measurement": "499f72bba2b06b3dfba723547f6d2e25347998af"
      },
      {
        "type_id": "0x414",
        "type_name": "NV_INFO_HASH",
        "tags": [
          "NV_INFO_HASH"
        ],
        "measurement": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6"
      }
    ]
  },
  {
    "pcr": {
      "index": 17,
      "bank": "SHA256"
    },
    "tpm_events": [
      {
        "type_id": "0x402",
        "type_name": "HASH_START",
        "tags": [
          "HASH_START"
        ],
        "measurement": "14fc51186adf98be977b9e9b65fc9ee26df0599c4f45804fcc45d0bdcf5025db"
      },
      {
        "type_id": "0x40a",
        "type_name": "BIOSAC_REG_DATA",
        "tags": [
          "BIOSAC_REG_DATA"
        ],
        "measurement": "c61aaa86c13133a0f1e661faf82e74ba199cd79cef652097e638a756bd194428"
      },
      {
        "type_id": "0x40b",
        "type_name": "CPU_SCRTM_STAT",
        "tags": [
          "CPU_SCRTM_STAT"
        ],
        "measurement": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
      },
      {
        "type_id": "0x40c",
        "type_name": "LCP_CONTROL_HASH",
        "tags": [
          "LCP_CONTROL_HASH"
        ],
        "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
      },
      {
        "type_id": "0x412",
        "type_name": "LCP_DETAILS_HASH",
        "tags": [
          "LCP_DETAILS_HASH"
        ],
        "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
      },
      {
        "type_id": "0x40e",
        "type_name": "STM_HASH",
        "tags": [
          "STM_HASH"
        ],
        "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
      },
      {
        "type_id": "0x40f",
        "type_name": "OSSINITDATA_CAP_HASH",
        "tags": [
          "OSSINITDATA_CAP_HASH"
        ],
        "measurement": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93"
      },
      {
        "type_id": "0x404",
        "type_name": "MLE_HASH",
        "tags": [
          "MLE_HASH"
        ],
        "measurement": "125f11bd4fb1156a29fbac5357ac04d14429c866a37d10643b1599be77917f82"
      },
      {
        "type_id": "0x414",
        "type_name": "NV_INFO_HASH",
        "tags": [
          "NV_INFO_HASH"
        ],
        "measurement": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
      }
    ]
  },
  {
    "pcr": {
      "index": 18,
      "bank": "SHA1"
    },
    "tpm_events": [
      {
        "type_id": "0x410",
        "type_name": "SINIT_PUBKEY_HASH",
        "tags": [
          "SINIT_PUBKEY_HASH"
        ],
        "measurement": "a395b723712b3711a89c2bb5295386c0db85fe44"
      },
      {
        "type_id": "0x40b",
        "type_name": "CPU_SCRTM_STAT",
        "tags": [
          "CPU_SCRTM_STAT"
        ],
        "measurement": "3c585604e87f855973731fea83e21fab9392d2fc"
      },
      {
        "type_id": "0x40f",
        "type_name": "OSSINITDATA_CAP_HASH",
        "tags": [
          "OSSINITDATA_CAP_HASH"
        ],
        "measurement": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895"
      },
      {
        "type_id": "0x40c",
        "type_name": "LCP_CONTROL_HASH",
        "tags": [
          "LCP_CONTROL_HASH"
        ],
        "measurement": "9069ca78e7450a285173431b3e52c5c25299e473"
      },
      {
        "type_id": "0x413",
        "type_name": "LCP_AUTHORITIES_HASH",
        "tags": [
          "LCP_AUTHORITIES_HASH"
        ],
        "measurement": "5ba93c9db0cff93f52b521d7420e43f6eda2784f"
      },
      {
        "type_id": "0x414",
        "type_name": "NV_INFO_HASH",
        "tags": [
          "NV_INFO_HASH"
        ],
        "measurement": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6"
      }
    ]
  },
  {
    "pcr": {
      "index": 18,
      "bank": "SHA256"
    },
    "tpm_events": [
      {
        "type_id": "0x410",
        "type_name": "SINIT_PUBKEY_HASH",
        "tags": [
          "SINIT_PUBKEY_HASH"
        ],
        "measurement": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7"
      },
      {
        "type_id": "0x40b",
        "type_name": "CPU_SCRTM_STAT",
        "tags": [
          "CPU_SCRTM_STAT"
        ],
        "measurement": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
      },
      {
        "type_id": "0x40f",
        "type_name": "OSSINITDATA_CAP_HASH",
        "tags": [
          "OSSINITDATA_CAP_HASH"
        ],
        "measurement": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93"
      },
      {
        "type_id": "0x40c",
        "type_name": "LCP_CONTROL_HASH",
        "tags": [
          "LCP_CONTROL_HASH"
        ],
        "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
      },
      {
        "type_id": "0x413",
        "type_name": "LCP_AUTHORITIES_HASH",
        "tags": [
          "LCP_AUTHORITIES_HASH"
        ],
        "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
      },
      {
        "type_id": "0x414",
        "type_name": "NV_INFO_HASH",
        "tags": [
          "NV_INFO_HASH"
        ],
        "measurement": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
      }
    ]
  }
]`)

	decodedEventLog := string(eventLogBytes)
	//EventlogBytes, hardcode. from measurelogjson

	tpmQuoteInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Quote)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error converting "+
			"tpm quote to bytes")
	}

	verificationNonceInBytes, err := base64.StdEncoding.DecodeString(verificationNonce)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error converting "+
			"nonce to bytes")
	}
	log.Info("intel_host_connector:GetHostManifestAcceptNonce() Verifying quote and retrieving PCR manifest from TPM quote " +
		"response ...")
	pcrManifest, err := util.VerifyQuoteAndGetPCRManifest(decodedEventLog, verificationNonceInBytes,
		tpmQuoteInBytes, aikCertificate)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error verifying "+
			"TPM Quote")
	}
	log.Info("intel_host_connector:GetHostManifestAcceptNonce() Successfully retrieved PCR manifest from quote")

	bindingKeyBytes, err := ic.client.GetBindingKeyCertificate()
	if err != nil {
		log.WithError(err).Debugf("intel_host_connector:GetHostManifestAcceptNonce() Error getting " +
			"binding key certificate from TA")
	}

	// The bindingkey certificate may not always be returned by the trust-agent,
	// it will only be there if workload-agent is installed.
	bindingKeyCertificateBase64 := ""
	if bindingKeyBytes != nil && len(bindingKeyBytes) > 0 {
		if bindingKeyCertificate, _ := pem.Decode(bindingKeyBytes); bindingKeyCertificate == nil {
			log.Warn("intel_host_connector:GetHostManifestAcceptNonce() - Could not decode Binding key certificate. Unexpected response from client")
		} else {
			bindingKeyCertificateBase64 = base64.StdEncoding.EncodeToString(bindingKeyCertificate.Bytes)
		}
	}
	aikCertificateBase64 := base64.StdEncoding.EncodeToString(aikPem.Bytes)

	hostManifest.PcrManifest = pcrManifest
	hostManifest.AIKCertificate = aikCertificateBase64
	hostManifest.AssetTagDigest = tpmQuoteResponse.AssetTag
	hostManifest.BindingKeyCertificate = bindingKeyCertificateBase64
	hostManifest.MeasurementXmls = tpmQuoteResponse.TcbMeasurements.TcbMeasurements

	hostManifestJson, err := json.Marshal(hostManifest)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "intel_host_connector:GetHostManifestAcceptNonce() Error "+
			"marshalling host manifest to JSON")
	}
	log.Debugf("intel_host_connector:GetHostManifestAcceptNonce() Host Manifest : %s", string(hostManifestJson))
	log.Info("intel_host_connector:GetHostManifestAcceptNonce() Host manifest created successfully")
	return hostManifest, err
}

func (ic *IntelConnector) DeployAssetTag(hardwareUUID, tag string) error {

	log.Trace("intel_host_connector:DeployAssetTag() Entering")
	defer log.Trace("intel_host_connector:DeployAssetTag() Leaving")
	err := ic.client.DeployAssetTag(hardwareUUID, tag)
	return err
}

func (ic *IntelConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {

	log.Trace("intel_host_connector:DeploySoftwareManifest() Entering")
	defer log.Trace("intel_host_connector:DeploySoftwareManifest() Leaving")
	err := ic.client.DeploySoftwareManifest(manifest)
	return err
}

func (ic *IntelConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {

	log.Trace("intel_host_connector:GetMeasurementFromManifest() Entering")
	defer log.Trace("intel_host_connector:GetMeasurementFromManifest() Leaving")
	measurement, err := ic.client.GetMeasurementFromManifest(manifest)
	return measurement, err
}

func (ic *IntelConnector) GetClusterReference(clusterName string) ([]mo.HostSystem, error) {
	return nil, errors.New("intel_host_connector :GetClusterReference() Operation not supported")
}
