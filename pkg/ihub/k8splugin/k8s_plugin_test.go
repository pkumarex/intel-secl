/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package k8splugin

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/k8s"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/k8s"
)

var sampleSamlCertPath = "../test/resources/saml_certificate.pem"
var sampleRootCertDirPath = "../test/resources/trustedCACert"
var privateKeyFilePath = "../test/resources/private_key.pem"
var publicKeyFilePath = "../test/resources/public_key.pem"
var k8scertFilePath = "../test/resources/k8scert.pem"

func setupMockValues(t *testing.T, portString string) (*KubernetesDetails, *HostDetails) {
	c := testutility.SetupMockK8sConfiguration(t, portString)
	hID := uuid.MustParse("42193CDA-7620-2540-C526-9B2F6936AECA")
	hostDetails := HostDetails{
		hostID:   hID,
		hostName: "worker-node1",
		hostIP:   "localhost",
		trusted:  true,
		AssetTags: map[string]string{
			"TAG_COUNTRY": "USA",
		},
		Trust: map[string]string{
			"TRUST_HOST_UNIQUE": "true",
		},
		SgxSupported: true,
		SgxEnabled:   true,
		FlcEnabled:   true,
		EpcSize:      "2.0GB",
		TcbUpToDate:  true,
	}

	kubernetes := KubernetesDetails{
		Config:         c,
		HostDetailsMap: map[string]HostDetails{hostDetails.hostName: hostDetails},
	}

	return &kubernetes, &hostDetails
}

func TestGetHostsFromKubernetes(t *testing.T) {
	server, portString := testutility.MockServer(t)
	k1, _ := setupMockValues(t, portString)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	urlPath := k1.Config.Endpoint.URL
	token := k1.Config.Endpoint.Token
	certFile := k1.Config.Endpoint.CertFile

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		t.Errorf("k8splugin/k8s_plugin_test:TestGetHostsFromKubernetes() Unable to parse url,error = %v", err)
		return
	}

	k8sClient, err := k8s.NewK8sClient(parsedUrl, token, certFile)
	if err != nil {
		t.Errorf("k8splugin/k8s_plugin_test:TestGetHostsFromKubernetes() Unable to create new k8client,error = %v", err)
		return
	}
	k1.K8sClient = k8sClient

	type args struct {
		k *KubernetesDetails
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get-host-from-k8s valid test",
			args: args{
				k: k1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GetHosts(tt.args.k)

			if (err != nil) != tt.wantErr {
				t.Errorf("k8splugin/k8s_plugin_test:TestGetHostsFromKubernetes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterHostReportsForKubernetes(t *testing.T) {
	server, port := testutility.MockServer(t)
	k1, h1 := setupMockValues(t, port)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	type args struct {
		k *KubernetesDetails
		h *HostDetails
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "filter-host-report-for-k8s valid test",
			args: args{
				k: k1,
				h: h1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := FilterHostReports(tt.args.k, tt.args.h, sampleRootCertDirPath, sampleSamlCertPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("k8splugin/k8s_plugin_test:TestFilterHostReportsForKubernetes(): error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateCRD(t *testing.T) {
	server, port := testutility.MockServer(t)
	k1, _ := setupMockValues(t, port)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()
	time.Sleep(1 * time.Second)

	var err error
	k1.PrivateKey, err = crypt.GetPrivateKeyFromPKCS8File(privateKeyFilePath)
	if err != nil {
		log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the privateKeyFile")
	}

	k1.PublicKeyBytes, err = ioutil.ReadFile(publicKeyFilePath)
	if err != nil {
		log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the publicKey")
	}

	k1.Config.Endpoint.CertFile = k8scertFilePath
	k1.Config.Endpoint.Token = k8sToken
	k1.Config.Endpoint.CRDName = "custom-isecl2"

	parsedUrl, err := url.Parse(k1.Config.Endpoint.URL)
	if err != nil {
		t.Error("k8splugin/k8s_plugin_test:TestUpdateCRD(): Unable to parse the url")
		return
	}

	k8sClient, err := k8s.NewK8sClient(parsedUrl, k1.Config.Endpoint.Token, k1.Config.Endpoint.CertFile)
	if err != nil {
		t.Error("k8splugin/k8s_plugin_test:TestUpdateCRD(): error in initializing client")
	}
	k1.K8sClient = k8sClient

	type args struct {
		k                *KubernetesDetails
		isSGXAttestation bool
		httpMethodType   string //should be set to either POST/PUT
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "update-crd valid test using PUT method",
			args: args{
				k: k1,
				isSGXAttestation: false,
				httpMethodType: "PUT",
			},
			wantErr: false,
		},
		{
			name: "update-crd valid test for SGX using PUT method",
			args: args{
				k: k1,
				isSGXAttestation: true,
				httpMethodType: "PUT",
			},
			wantErr: false,
		},
		{
			name: "update-crd valid test using POST method",
			args: args{
				k: k1,
				isSGXAttestation: false,
				httpMethodType: "POST",
			},
			wantErr: false,
		},
		{
			name: "update-crd valid test for SGX using POST method ",
			args: args{
				k: k1,
				isSGXAttestation: true,
				httpMethodType: "POST",
			},
			wantErr: false,
		},
		{
			name: "update-crd negative test 1",
			args: args{
				k: &KubernetesDetails{
					Config: &config.Configuration{
						Endpoint: config.Endpoint{
							URL: "",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "update-crd negative test 2",
			args: args{
				k: &KubernetesDetails{
					Config: &config.Configuration{
						Endpoint: config.Endpoint{
							URL: "://zz",
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			if tt.args.isSGXAttestation {
				tt.args.k.Config.AttestationService.AttestationType = "SGX"
			} else {
				tt.args.k.Config.AttestationService.AttestationType = "HVS"
			}

			if tt.args.httpMethodType == "POST" {
				tt.args.k.Config.Endpoint.CRDName = "custom-isecl-not-found"
			} else if tt.args.httpMethodType == "PUT" {
				tt.args.k.Config.Endpoint.CRDName = "custom-isecl2"
			}

			log.Info(tt.args.k.Config.Endpoint.CRDName)
			err := UpdateCRD(tt.args.k)

			if (err != nil) != tt.wantErr {
				t.Errorf("k8splugin/k8s_plugin_test:TestUpdateCRD(): error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func TestKubePluginInit(t *testing.T) {
	server, port := testutility.MockServer(t)
	c := testutility.SetupMockK8sConfiguration(t, port)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	type args struct {
		configuration      *config.Configuration
		isSGXAttestation   bool
		PrivateKeyLocation string
		PublicKeyLocation  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{

		{
			name: "k8-plugin-init valid test",
			args: args{
				configuration:      c,
				PrivateKeyLocation: "privateKey.pem",
				PublicKeyLocation:  "publicKey.pem",
			},
			wantErr: false,
		},
		{
			name: "k8-plugin-init valid test for SGX",
			args: args{
				configuration:      c,
				PrivateKeyLocation: "privateKey.pem",
				PublicKeyLocation:  "publicKey.pem",
			},
			wantErr: false,
		},
		{
			name: "k8-plugin-init negative test",
			args: args{
				configuration:      &config.Configuration{},
				PrivateKeyLocation: "",
				PublicKeyLocation:  "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			samlFile, err := ioutil.TempFile("", "samlCert.pem")
			if err != nil {
				t.Log("k8splugin/k8s_plugin_test:TestKubePluginInit(): error in reading the file")
			}
			defer func() {
				err := os.Remove(samlFile.Name())
				if err != nil {
					t.Errorf("Error removing file")
				}
			}()
			kPlugin := KubernetesDetails{
				Config: tt.args.configuration,
			}

			kPlugin.PrivateKey, err = crypt.GetPrivateKeyFromPKCS8File(privateKeyFilePath)
			if err != nil {
				log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestKubePluginInit() Error in reading the privateKeyFile")
			}

			kPlugin.PublicKeyBytes, err = ioutil.ReadFile(publicKeyFilePath)
			if err != nil {
				log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestKubePluginInit() Error in reading the publicKey")
			}

			apiURL := kPlugin.Config.Endpoint.URL
			token := kPlugin.Config.Endpoint.Token
			certFile := kPlugin.Config.Endpoint.CertFile

			apiUrl, err := url.Parse(apiURL)
			if err != nil {
				log.WithError(err).Error("k8splugin/k8s_plugin_test:TestKubePluginInit() Unable to parse Kubernetes api url")
			}

			k8sClient, err := k8s.NewK8sClient(apiUrl, token, certFile)
			if err != nil {
				log.WithError(err).Error("k8splugin/k8s_plugin_test:TestKubePluginInit() Error in initializing the Kubernetes client")
			}
			kPlugin.K8sClient = k8sClient

			if tt.args.isSGXAttestation {
				tt.args.configuration.AttestationService.AttestationType = "SGX"
			} else {
				tt.args.configuration.AttestationService.AttestationType = "HVS"
			}

			err = SendDataToEndPoint(kPlugin, sampleRootCertDirPath, sampleSamlCertPath)

			if err != nil && tt.wantErr == false {
				t.Errorf("k8splugin/k8s_plugin_test:TestKubePluginInit(): error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestPostCRD(t *testing.T) {
	server, port := testutility.MockServer(t)
	k1, _ := setupMockValues(t, port)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	c := k1.Config
	crdName := c.Endpoint.CRDName
	var crdResponse model.CRD

	crdResponse.APIVersion = "crd.isecl.intel.com/v1beta1"
	crdResponse.Kind = "HostAttributesCrd"
	crdResponse.Metadata.Name = crdName
	crdResponse.Metadata.Namespace = "default"
	var hostList []model.Host
	var host model.Host
	host.HostName = "testHost"
	host.AssetTags = map[string]string{
		"TAG_COUNTRY": "USA",
	}
	host.HardwareFeatures = nil
	host.Trust = map[string]string{
		"TRUST_HOST_UNIQUE": "true",
	}
	trustStatus := true
	host.Trusted = &trustStatus
	host.HvsTrustValidTo = new(time.Time)
	*host.HvsTrustValidTo = time.Now().Add(time.Hour * 24)
	hostList = append(hostList, host)
	crdResponse.Spec.HostList = hostList

	type args struct {
		k              *KubernetesDetails
		crd            *model.CRD
		PrivateKeyFile string
		PublicKeyFile  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "post-crd valid test 1",
			args: args{
				k:   k1,
				crd: &crdResponse,
			},
			wantErr: false,
		},

		{
			name: "post-crd valid test 2",
			args: args{
				k:              k1,
				crd:            &crdResponse,
				PrivateKeyFile: "privateKey.pem",
				PublicKeyFile:  "publicKey.pem",
			},
			wantErr: false,
		},
		{
			name: "post-crd negative test 1",
			args: args{
				k: &KubernetesDetails{
					AuthToken: "",
					Config: &config.Configuration{
						Endpoint: config.Endpoint{
							URL:      "",
							Token:    "",
							CertFile: "",
						},
					},
				},
				crd: &crdResponse,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			parsedUrl, err := url.Parse(tt.args.k.Config.Endpoint.URL)
			if err != nil {
				t.Errorf("k8splugin/k8s_plugin_test:TestPostCRD() unable to parse url,error = %v", err)
				return
			}

			if tt.args.k.Config.Endpoint.CertFile != "" {
				k8sClient, err := k8s.NewK8sClient(parsedUrl, tt.args.k.Config.Endpoint.Token, k8scertFilePath)
				if err != nil {
					t.Errorf("k8splugin/k8s_plugin_test:TestPostCRD() Unable to init k8client,error = %v", err)
					return
				}
				tt.args.k.K8sClient = k8sClient
			} else {
				k8s.NewK8sClient(parsedUrl, tt.args.k.Config.Endpoint.Token, tt.args.k.Config.Endpoint.CertFile)
			}

			if tt.args.PrivateKeyFile != "" {

				tt.args.k.PrivateKey, err = crypt.GetPrivateKeyFromPKCS8File(privateKeyFilePath)
				if err != nil {
					log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the privateKeyFile")
				}

				tt.args.k.PublicKeyBytes, err = ioutil.ReadFile(publicKeyFilePath)
				if err != nil {
					log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the publicKey")
				}

			}

			if err := PostCRD(tt.args.k, tt.args.crd); (err != nil) != tt.wantErr {
				t.Errorf("k8splugin/k8s_plugin_test:TestPostCRD() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetSignedTrustReport(t *testing.T) {
	trustStatus := true
	validTo := time.Now().Add(time.Hour * 24)
	h1 := model.Host{
		HostName: "host1",
		Trusted:  &trustStatus,
		AssetTags: map[string]string{
			"TAG_COUNTRY": "USA",
		},
		Trust: map[string]string{
			"TRUST_HOST_UNIQUE": "true",
		},
		HvsTrustValidTo: &validTo,
	}
	type args struct {
		h model.Host
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get-signed-report valid test 1",
			args: args{
				h: h1,
			},
			wantErr: false,
		},
		{
			name: "get-signed-report negative test 2",
			args: args{
				h: h1,
			},
			wantErr: true,
		},
		{
			name: "get-signed-report valid test 3",
			args: args{
				h: h1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		kDetails := KubernetesDetails{}

		if tt.name == "get-signed-report valid test 1" {
			var err error

			kDetails.PrivateKey, err = crypt.GetPrivateKeyFromPKCS8File(privateKeyFilePath)
			if err != nil {
				log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the privateKeyFile")
			}

			kDetails.PublicKeyBytes, err = ioutil.ReadFile(publicKeyFilePath)
			if err != nil {
				log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the publicKey")
			}

		} else if tt.name == "get-signed-report negative test 2" {
			kDetails.PrivateKey = []byte("")
		} else {
			var err error
			kDetails.PrivateKey, err = crypt.GetPrivateKeyFromPKCS8File(privateKeyFilePath)
			if err != nil {
				log.WithError(err).Error(err, "k8splugin/k8s_plugin_test:TestGetSignedTrustReport() Error in reading the privateKeyFile")
			}
			kDetails.PublicKeyBytes = []byte("")
		}
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetSignedTrustReport(tt.args.h, &kDetails, "HVS")
			if (err != nil) != tt.wantErr {
				t.Errorf("k8splugin/k8s_plugin_test:TestGetSignedTrustReport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var k8sToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

func TestPutCRD(t *testing.T) {

	var crdResponse model.CRD
	crdResponse.APIVersion = "crd.isecl.intel.com/v1beta1"
	crdResponse.Kind = "HostAttributesCrd"
	crdResponse.Metadata.Name = "custom-isecl"
	crdResponse.Metadata.Namespace = "default"

	server, port := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()
	type args struct {
		k   *KubernetesDetails
		crd *model.CRD
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		server  bool
	}{
		{
			name: "put-crd negative test",
			args: args{
				k: &KubernetesDetails{
					AuthToken: "",
					Config: &config.Configuration{
						Endpoint: config.Endpoint{
							URL:      "",
							Token:    "",
							CertFile: "",
						},
					},
				},
				crd: &crdResponse,
			},
			wantErr: true,
			server:  true,
		},
		{
			name: "put-crd valid test",
			args: args{
				k: &KubernetesDetails{
					AuthToken: "",
					Config: &config.Configuration{
						Endpoint: config.Endpoint{
							URL:      "http://localhost" + port + "/",
							Token:    k8sToken,
							CertFile: "k8sCert.pem",
						},
					},
				},
				crd: &crdResponse,
			},
			wantErr: false,
			server:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedUrl, err := url.Parse(tt.args.k.Config.Endpoint.URL)
			if err != nil {
				t.Errorf("k8splugin/k8s_plugin_test:TestPutCRD() unable to parse url,error = %v", err)
				return
			}
			if tt.server == true {
				if tt.args.k.Config.Endpoint.CertFile != "" {
					k8sClient, err := k8s.NewK8sClient(parsedUrl, tt.args.k.Config.Endpoint.Token, k8scertFilePath)
					if err != nil {
						t.Errorf("k8splugin/k8s_plugin_test:TestPutCRD() Unable to init k8client,error = %v", err)
						return
					}
					tt.args.k.K8sClient = k8sClient
				} else {
					k8s.NewK8sClient(parsedUrl, tt.args.k.Config.Endpoint.Token, tt.args.k.Config.Endpoint.CertFile)
				}
			}
			if err := PutCRD(tt.args.k, tt.args.crd); (err != nil) != tt.wantErr {
				t.Errorf("PutCRD() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
