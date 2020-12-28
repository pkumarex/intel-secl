/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Run unit tests: go test github.com/intel-secl/intel-secl/v3/pkg/lib/verifier
//
// coverage report...
// go test github.com/intel-secl/intel-secl/v3/pkg/lib/verifier -v -coverpkg=github.com/intel-secl/intel-secl/v3/pkg/lib/verifier -coverprofile cover.out
// go tool cover -func cover.out
//
import (
	"crypto/x509"
	"encoding/json"
	"io/ioutil"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	//"sort"
	"testing"
)

func TestMockExample(t *testing.T) {

	hostManifest := types.HostManifest{}
	signedFlavor := hvs.SignedFlavor{}
	certficates := VerifierCertificates{}
	trustReport := hvs.TrustReport{}

	v, err := NewMockVerifier(certficates)
	assert.NoError(t, err)

	v.On("Verify", &hostManifest, &signedFlavor, mock.Anything).Return(&trustReport, nil)

	report, err := v.Verify(&hostManifest, &signedFlavor, true)
	assert.NoError(t, err)
	assert.NotNil(t, report)
}

func TestVerifierIntegrationIntel20(t *testing.T) {

	verifierCertificates, err := createVerifierCertificates(t,
		"test_data/intel20/PrivacyCA.pem",
		"test_data/intel20/flavor-signer.crt.pem",
		"test_data/intel20/cms-ca-cert.pem",
		"test_data/intel20/tag-cacerts.pem")
	if err != nil {
		assert.FailNowf(t, "Could not create verifier certificates for intel 2.0", "%s", err)
	}

	runVerifierIntegrationTest(t,
		"test_data/intel20/host_manifest.json",
		"test_data/intel20/signed_flavors.json",
		"test_data/intel20/trust_report.json",
		verifierCertificates)
}

func TestVerifierIntegrationVMWare12(t *testing.T) {

	verifierCertificates, err := createVerifierCertificates(t,
		"test_data/vmware12/PrivacyCA.pem",
		"test_data/vmware12/flavor-signer.crt.pem",
		"test_data/vmware12/cms-ca-cert.pem",
		"test_data/vmware12/tag-cacerts.pem")
	if err != nil {
		assert.FailNowf(t, "Could not create verifier certificates for vmware 1.2", "%s", err)
	}

	runVerifierIntegrationTest(t,
		"test_data/vmware12/host_manifest.json",
		"test_data/vmware12/signed_flavors.json",
		"test_data/vmware12/trust_report.json",
		verifierCertificates)
}

func TestVerifierIntegrationVMWare20(t *testing.T) {

	verifierCertificates, err := createVerifierCertificates(t,
		"test_data/vmware20/PrivacyCA.pem",
		"test_data/vmware20/flavor-signer.crt.pem",
		"test_data/vmware20/cms-ca-cert.pem",
		"test_data/vmware20/tag-cacerts.pem")
	if err != nil {
		assert.FailNowf(t, "Could not create verifier certificates for vmware 2.0", "%s", err)
	}

	runVerifierIntegrationTest(t,
		"test_data/vmware20/host_manifest.json",
		"test_data/vmware20/signed_flavors.json",
		"test_data/vmware20/trust_report.json",
		verifierCertificates)
}

func runVerifierIntegrationTest(t *testing.T,
	hostManifestFile string,
	signedFlavorsFile string,
	trustReportFile string,
	verifierCertificates VerifierCertificates) {

	var hostManifest types.HostManifest
	var signedFlavors []hvs.SignedFlavor
	var javaTrustReports map[string]hvs.TrustReport

	manifestJSON, err := ioutil.ReadFile(hostManifestFile)
	if err != nil {
		assert.FailNowf(t, "Could not load host manifest file", "%s", err)
	}

	err = json.Unmarshal(manifestJSON, &hostManifest)
	if err != nil {
		assert.FailNowf(t, "Could not unmarshal host manifest json", "%s", err)
	}

	flavorsJSON, err := ioutil.ReadFile(signedFlavorsFile)
	if err != nil {
		assert.FailNowf(t, "Could not load signed flavors file", "%s", err)
	}

	err = json.Unmarshal(flavorsJSON, &signedFlavors)
	if err != nil {
		assert.FailNowf(t, "Could not unmarshal host manifest json", "%s", err)
	}

	v, err := NewVerifier(verifierCertificates)
	if err != nil {
		assert.FailNowf(t, "Could not unmarshal host manifest json", "%s", err)
	}

	javaTrustReportsJSON, err := ioutil.ReadFile(trustReportFile)
	if err != nil {
		assert.FailNowf(t, "Could load test_data/trust_report.json: %s", err.Error())
	}

	err = json.Unmarshal(javaTrustReportsJSON, &javaTrustReports)
	if err != nil {
		assert.FailNowf(t, "Could not unmarshal trust report manifest json", "%s", err)
	}

	// loop over all of the signed flavors and compare them against
	// an actual trust-report from java/hvs.
	for _, signedFlavor := range signedFlavors {
		t.Logf("==> Verifying flavor %s...", signedFlavor.Flavor.Meta.Description[model.FlavorPart].(string))

		// This test uses real data from java/hvs in the 'test_data' directory.  It will not
		// be possible to apply the FlavorTrusted rule due to differences in json serialization
		// betweek go/java.  So, disable flavor signature verification by seeting
		// 'skipFlavorSignatureVerification' to true.
		trustReport, err := v.Verify(&hostManifest, &signedFlavor, true)
		if err != nil {
			assert.FailNowf(t, "Verify failed", "%s", err)
		}

		assert.NotNil(t, trustReport)
		assert.True(t, trustReport.Trusted)

		if !trustReport.Trusted {
			for _, result := range trustReport.Results {
				for _, fault := range result.Faults {
					t.Logf("==> Fault: %s", fault.Name)
				}
			}
		}

		//-------------------------------------------------------------------------------
		// uncomment this code sort and write the results to support troubleshooting
		//-------------------------------------------------------------------------------

		// expectedTrustReport, ok := javaTrustReports[signedFlavor.Flavor.Meta.Description.FlavorPart]
		// if !ok {
		// 	assert.FailNowf(t, "Could not find expected trust report", "FlavorPart %s: %s", signedFlavor.Flavor.Meta.Description.FlavorPart, err)
		// }

		// sort.Sort(ResultsSort(trustReport.Results))
		// sort.Sort(ResultsSort(expectedTrustReport.Results))

		// fileName := signedFlavor.Flavor.Meta.Description.FlavorPart + "." + signedFlavor.Flavor.Meta.ID.String()

		// expectedTrustReportJSON, err := json.MarshalIndent(expectedTrustReport, "", "  ")
		// assert.NoError(t, err)
		// ioutil.WriteFile("test_data/" + fileName + ".expected.trust_report.json", expectedTrustReportJSON, 0644)

		// actualTrustReportJSON, err := json.MarshalIndent(trustReport, "", "  ")
		// assert.NoError(t, err)
		// ioutil.WriteFile("test_data/" + fileName + ".actual.trust_report.json", actualTrustReportJSON, 0644)
	}
}

func createVerifierCertificates(t *testing.T,
	privacyCAFile string,
	flavorSignerCertFile string,
	cmsCAsFile string,
	tagCertsFile string) (VerifierCertificates, error) {

	//
	// Privacy CA
	//
	privacyCAsPemBytes, err := ioutil.ReadFile(privacyCAFile)
	if err != nil {
		assert.FailNowf(t, "Could parse privacy file '%s': %s", privacyCAFile, err.Error())
	}

	privacyCACertificates := x509.NewCertPool()
	ok := privacyCACertificates.AppendCertsFromPEM(privacyCAsPemBytes)
	if !ok {
		assert.FailNow(t, "Error loading privacy CA")
	}

	//
	// Flavor Signing
	//
	// The verifier needs two things, the flavor signing certificate and a list
	// of intermediate CAs (flavorCACertificates).  The HVS file layout is...
	// - flavor-signer.crt.pem contains two pem blocks.  The first is the flavor
	//   signing certificate.  The second is an intermediate ca that needs to be
	//   added to 'flavorCACertificates'.
	// - cms-ca-cert.pem is the rest of the intermediate CAs.
	//
	// The following code parses those files...

	flavorSigningPemBytes, err := ioutil.ReadFile(flavorSignerCertFile)
	if err != nil {
		assert.FailNowf(t, "Could load flavor signing cert '%s': %s", flavorSignerCertFile, err.Error())
	}

	flavorSigningCertificate, flavorCACertificates, err := crypt.GetCertAndChainFromPem(flavorSigningPemBytes)
	if err != nil {
		assert.FailNowf(t, "Error building flavor signing certificate: %s", err.Error())
	}

	flavorCAsPemBytes, err := ioutil.ReadFile(cmsCAsFile)
	if err != nil {
		assert.FailNowf(t, "Could load cms CA file '%s': %s", cmsCAsFile, err.Error())
	}

	ok = flavorCACertificates.AppendCertsFromPEM(flavorCAsPemBytes)
	if !ok {
		assert.FailNow(t, "Error loading flavor CAs")
	}

	//
	// Asset Tags
	//
	assetTagPemBytes, err := ioutil.ReadFile(tagCertsFile)
	if err != nil {
		assert.FailNowf(t, "Could load tag certs file '%s': %s", tagCertsFile, err.Error())
	}

	assetTagCACertificates := x509.NewCertPool()
	ok = assetTagCACertificates.AppendCertsFromPEM(assetTagPemBytes)
	if !ok {
		assert.FailNow(t, "Error loading asset tag certs")
	}

	return VerifierCertificates{
		PrivacyCACertificates:    privacyCACertificates,
		FlavorSigningCertificate: flavorSigningCertificate,
		AssetTagCACertificates:   assetTagCACertificates,
		FlavorCACertificates:     flavorCACertificates,
	}, nil
}

//-------------------------------------------------------------------------------------------------
// M O C K   V E R I F I E R
//-------------------------------------------------------------------------------------------------

type MockVerifier struct {
	mock.Mock
	certificates VerifierCertificates
}

func NewMockVerifier(certificates VerifierCertificates) (*MockVerifier, error) {
	return &MockVerifier{certificates: certificates}, nil
}

func (v *MockVerifier) Verify(hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor, skipFlavorSignatureVerification bool) (*hvs.TrustReport, error) {
	args := v.Called(hostManifest, signedFlavor, skipFlavorSignatureVerification)
	return args.Get(0).(*hvs.TrustReport), args.Error(1)
}

//-------------------------------------------------------------------------------------------------
// R E S U L T S   S O R T
//-------------------------------------------------------------------------------------------------

type ResultsSort []hvs.RuleResult

func (results ResultsSort) Len() int {
	return len(results)
}

func (results ResultsSort) Swap(i, j int) {
	results[i], results[j] = results[j], results[i]
}

func (results ResultsSort) Less(i, j int) bool {

	sortKey1 := results[i].Rule.Name
	sortKey2 := results[j].Rule.Name

	if results[i].Rule.ExpectedPcr != nil && results[j].Rule.ExpectedPcr != nil {
		sortKey1 += ":" + string(results[i].Rule.ExpectedPcr.PcrBank) + ":" + string(results[i].Rule.ExpectedPcr.Index)
		sortKey2 += ":" + string(results[j].Rule.ExpectedPcr.PcrBank) + ":" + string(results[j].Rule.ExpectedPcr.Index)
	}

	return sortKey1 < sortKey2
}
