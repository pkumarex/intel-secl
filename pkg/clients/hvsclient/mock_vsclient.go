/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/stretchr/testify/mock"
)

//-------------------------------------------------------------------------------------------------
// Mocked Client Factory:  Assumes that unit tests will populate the factory with mocked
// implementations of the clients as needed.
//-------------------------------------------------------------------------------------------------
type MockedVSClientFactory struct {
	MockedCACertificatesClient  CACertificatesClient
	MockedCertifyHostKeysClient CertifyHostKeysClient
	MockedReportsClient         ReportsClient
	MockedHostsClient           HostsClient
	MockedFlavorsClient         FlavorsClient
	MockedManifestsClient       ManifestsClient
	MockedPrivacyCAClient       PrivacyCAClient
}

func (factory MockedVSClientFactory) HostsClient() (HostsClient, error) {
	return factory.MockedHostsClient, nil
}

func (factory MockedVSClientFactory) FlavorsClient() (FlavorsClient, error) {
	return factory.MockedFlavorsClient, nil
}

func (factory MockedVSClientFactory) ManifestsClient() (ManifestsClient, error) {
	return factory.MockedManifestsClient, nil
}

func (factory MockedVSClientFactory) PrivacyCAClient() (PrivacyCAClient, error) {
	return factory.MockedPrivacyCAClient, nil
}

func (factory MockedVSClientFactory) CACertificatesClient() (CACertificatesClient, error) {
	return factory.MockedCACertificatesClient, nil
}

func (factory MockedVSClientFactory) CertifyHostKeysClient() (CertifyHostKeysClient, error) {
	return factory.MockedCertifyHostKeysClient, nil
}

func (factory MockedVSClientFactory) ReportsClient() (ReportsClient, error) {
	return factory.MockedReportsClient, nil
}

//-------------------------------------------------------------------------------------------------
// Mocked Hosts interface
//-------------------------------------------------------------------------------------------------
type MockedHostsClient struct {
	mock.Mock
}

// Can be mocked in unit tests similar to...
// mockedHostsClient := new(hvsclient.MockedHostsClient)
// mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvsclient.HostCollection {Hosts: []hvsclient.Host{}}, nil)
func (mock MockedHostsClient) SearchHosts(hostFilterCriteria *models.HostFilterCriteria) (*hvs.HostCollection, error) {
	args := mock.Called(hostFilterCriteria)
	return args.Get(0).(*hvs.HostCollection), args.Error(1)
}

// Can be mocked in unit tests similar to...
// mockedHostsClient := new(hvsclient.MockedHostsClient)
// mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvsclient.Host{Id:"068b5e88-1886-4ac2-a908-175cf723723f"}, nil)
func (mock MockedHostsClient) CreateHost(hostCreateRequest *hvs.HostCreateRequest) (*hvs.Host, error) {
	args := mock.Called(hostCreateRequest)
	return args.Get(0).(*hvs.Host), args.Error(1)
}

func (mock MockedHostsClient) UpdateHost(host *hvs.Host) (*hvs.Host, error) {
	args := mock.Called(host)
	return args.Get(0).(*hvs.Host), args.Error(1)
}

//-------------------------------------------------------------------------------------------------
// Mocked Flavors interface
//-------------------------------------------------------------------------------------------------
type MockedFlavorsClient struct {
	mock.Mock
}

func (mock MockedFlavorsClient) CreateFlavor(flavorCreateRequest *models.FlavorCreateRequest) (hvs.FlavorCollection, error) {
	args := mock.Called(flavorCreateRequest)
	return args.Get(0).(hvs.FlavorCollection), args.Error(0)
}

//-------------------------------------------------------------------------------------------------
// Mocked Manifests interface
//-------------------------------------------------------------------------------------------------
type MockedManifestsClient struct {
	mock.Mock
}

func (mock MockedManifestsClient) GetManifestXmlById(manifestUUID string) ([]byte, error) {
	args := mock.Called(manifestUUID)
	return args.Get(0).([]byte), args.Error(1)
}

func (mock MockedManifestsClient) GetManifestXmlByLabel(manifestLabel string) ([]byte, error) {
	args := mock.Called(manifestLabel)
	return args.Get(0).([]byte), args.Error(1)
}
