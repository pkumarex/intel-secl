/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keytransfer

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	samlLib "github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/wlagent"
)

var defaultLog = log.GetDefaultLogger()

//IsTrustedByHvs verifies if the client can be trusted for transfer
func IsTrustedByHvs(saml string, samlReport *samlLib.Saml, keyId uuid.UUID, config domain.KeyControllerConfig, remoteManager *keymanager.RemoteManager) (bool, *x509.Certificate) {
	defaultLog.Trace("keytransfer/transfer_with_saml:IsTrustedByHvs() Entering")
	defer defaultLog.Trace("keytransfer/transfer_with_saml:IsTrustedByHvs() Leaving")

	usagePolicyTags := make(map[string]string, 0)
	key, _ := remoteManager.RetrieveKey(keyId)
	if key != nil && key.Usage != "" {
		usagePolicies := strings.Split(key.Usage, ",")

		// create a map for the usage policies
		for _, usagePolicy := range usagePolicies {
			tagKeyValuePair := strings.Split(usagePolicy, ":")
			usagePolicyTags[strings.ToLower(tagKeyValuePair[0])] = tagKeyValuePair[1]
		}
	}

	//Remove Indentation from Request body
	pattern := regexp.MustCompile(`( *)<`)
	saml = pattern.ReplaceAllString(saml, "<")
	verified := verifySamlSignature(saml, config.SamlCertsDir, config.TrustedCaCertsDir)
	if !verified {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Invalid signature on trust report")
		return false, nil
	}

	var err error
	var assetTagDeployed bool
	tagsDeployedOnHost := make(map[string]string, 0)
	var bindingKeyCertBytes, aikCertBytes []byte
	for _, as := range samlReport.Attribute {

		switch as.Name {
			case "TRUST_OVERALL" :
				if as.AttributeValue != "true" {
					defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Host is not trusted")
					return false, nil
				}
			case "tpmVersion" :
				if as.AttributeValue != "2.0" {
					defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() TPM version not supported")
					return false, nil
				}
			case "Binding_Key_Certificate" :
				bindingKeyCertBytes, err = base64.StdEncoding.DecodeString(as.AttributeValue)
				if err != nil {
					defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Unable to decode Binding Key Certificate")
					return false, nil
				}
			case "AIK_Certificate" :
				aikCertBytes, err = base64.StdEncoding.DecodeString(as.AttributeValue)
				if err != nil {
					defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Unable to decode AIK certificate")
					return false, nil
				}
			case "TRUST_ASSET_TAG" :
				// check if asset tag is deployed on the host
				if as.AttributeValue == "true" {
					assetTagDeployed = true
				}
			default:
				// get the list of deployed tags on the host and add it in the map
				if strings.HasPrefix(as.Name, "TAG_") {
					tagsDeployedOnHost[strings.ToLower(strings.TrimPrefix(as.Name, "TAG_"))] = as.AttributeValue
				}
		}
	}

	if len(aikCertBytes) == 0 {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Assertion does not include AIK Certificate")
		return false, nil
	}

	aikCert, err := x509.ParseCertificate(aikCertBytes)
	if err != nil {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Unable to parse AIK certificate")
		return false, nil
	}

	verified = verifySignature(aikCert, config.TpmIdentityCertsDir)
	if !verified {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() AIK certificate not verified by any trusted authority")
		return false, nil
	}

	if len(bindingKeyCertBytes) == 0 {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() No binding key certificate in trust report")
		return false, nil
	}

	bindingKeyCert, err := x509.ParseCertificate(bindingKeyCertBytes)
	if err != nil {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Unable to parse Binding Key certificate")
		return false, nil
	}

	verified = verifySignature(bindingKeyCert, config.TpmIdentityCertsDir)
	if !verified {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Binding key certificate not verified by any trusted authority")
		return false, nil
	}

	verified = verifyTpmBindingKeyCertificate(bindingKeyCert, aikCert)
	if !verified {
		defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Binding key certificate has invalid attributes or cannot be verified with the AIK")
		return false, nil
	}

	if len(usagePolicyTags) != 0 {
		if !assetTagDeployed {
			defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Asset tags are not deployed on the host, but a usage policy is defined for the requested key")
			return false, nil
		}

		// check if all the keys in tagsDeployedOnHost exist in usagePolicyTags and their values match
		for key, value := range usagePolicyTags {
			if v, ok := tagsDeployedOnHost[key]; !ok || strings.ToLower(v) != strings.ToLower(value) {
				defaultLog.Error("keytransfer/transfer_with_saml:IsTrustedByHvs() Usage policy requirements of the key does not match with tags deployed on the host")
				return false, nil
			}
		}
	}

	return true, bindingKeyCert
}

//verifySamlSignature verifies signature of the saml report
func verifySamlSignature(saml, samlCertsDir, trustedCaCertsDir string) bool {
	defaultLog.Trace("keytransfer/transfer_with_saml:VerifySamlSignature() Entering")
	defer defaultLog.Trace("keytransfer/transfer_with_saml:VerifySamlSignature() Leaving")

	samlCertFiles, err := ioutil.ReadDir(samlCertsDir)
	if err != nil {
		defaultLog.WithError(err).Error("keytransfer/transfer_with_saml:VerifySamlSignature() Error while reading the directory: ")
		return false
	}

	var verified bool
	for _, samlCertFile := range samlCertFiles {
		if isValidSaml := samlLib.VerifySamlSignature(saml, filepath.Join(samlCertsDir, samlCertFile.Name()), trustedCaCertsDir); isValidSaml {
			verified = true
		}
	}

	return verified
}

//verifySignature verifies the signature of certificate
func verifySignature(cert *x509.Certificate, signingCertsDir string) bool {
	defaultLog.Trace("keytransfer/transfer_with_saml:VerifySignature() Entering")
	defer defaultLog.Trace("keytransfer/transfer_with_saml:VerifySignature() Leaving")

	signingCerts, err := crypt.GetCertsFromDir(signingCertsDir)
	if err != nil {
		defaultLog.WithError(err).Errorf("keytransfer/transfer_with_saml:VerifySignature() Error retrieving signing certificates from %s", signingCertsDir)
		return false
	}

	verifyRootCAOpts := x509.VerifyOptions{
		Roots: crypt.GetCertPool(signingCerts),
	}

	if _, err := cert.Verify(verifyRootCAOpts); err != nil {
		defaultLog.WithError(err).Error("keytransfer/transfer_with_saml:VerifySignature() Error verifying certificate signature")
		return false
	}

	return true
}

//verifyTpmBindingKeyCertificate verifies if the binding key is generated from same TPM as aik
func verifyTpmBindingKeyCertificate(keyCert, aikCert *x509.Certificate) bool {
	defaultLog.Trace("keytransfer/transfer_with_saml:verifyTpmBindingKeyCertificate() Entering")
	defer defaultLog.Trace("keytransfer/transfer_with_saml:verifyTpmBindingKeyCertificate() Leaving")

	keyInfoOid := asn1.ObjectIdentifier{2, 5, 4, 133, 3, 2, 41}
	keySigOid := asn1.ObjectIdentifier{2, 5, 4, 133, 3, 2, 41, 1}

	tpmCertifyKeyInfo := crypt.GetCertExtension(keyCert, keyInfoOid)
	tpmCertifyKeySignature := crypt.GetCertExtension(keyCert, keySigOid)

	regKeyInfo := model.RegisterKeyInfo{
		TpmCertifyKey:          tpmCertifyKeyInfo,
		TpmCertifyKeySignature: tpmCertifyKeySignature,
		TpmVersion:             "2.0",
	}

	certifyKey20, _ := privacyca.NewCertifyKey(regKeyInfo)
	verified, err := certifyKey20.IsCertifiedKeySignatureValid(aikCert)
	if err != nil || !verified {
		defaultLog.WithError(err).Error("keytransfer/transfer_with_saml:verifyTpmBindingKeyCertificate() TPM Binding Public Key cannot be verified by the given AIK public key")
		return false
	}

	if !certifyKey20.IsTpmGeneratedKey(){
		defaultLog.Error("keytransfer/transfer_with_saml:verifyTpmBindingKeyCertificate() TPM Binding Key has incorrect attributes")
		return false
	}

	return true
}
