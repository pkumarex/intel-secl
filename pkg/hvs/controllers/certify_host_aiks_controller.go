/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	libPrivacyca "github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type CertifyHostAiksController struct {
	CertStore          *models.CertificatesStore
	ECStore            domain.TpmEndorsementStore
	AikCertValidity    int
	AikRequestsDirPath string
}

func NewCertifyHostAiksController(certStore *models.CertificatesStore, ecstore domain.TpmEndorsementStore, aikCertValidity int, aikReqsDir string) *CertifyHostAiksController {
	defaultLog.Trace("controllers/certify_host_aiks_controller:NewCertifyHostAiksController() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:NewCertifyHostAiksController() Leaving")
	// CertStore should have an entry for Privacyca key

	var err error
	pcaKey, pcaCert, err := certStore.GetKeyAndCertificates(models.CaCertTypesPrivacyCa.String())
	if err != nil || pcaKey == nil || pcaCert == nil {
		defaultLog.Errorf("Error while retrieving certificate and key for certType %s", models.CaCertTypesPrivacyCa.String())
		return nil
	}
	if _, found := (*certStore)[models.CaCertTypesEndorsementCa.String()]; !found {
		defaultLog.Errorf("controllers/certify_host_aiks_controller:NewCertifyHostAiksController() %s : Endorsement Certificate not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	return &CertifyHostAiksController{CertStore: certStore, ECStore: ecstore, AikCertValidity: aikCertValidity, AikRequestsDirPath: aikReqsDir}
}

func (certifyHostAiksController *CertifyHostAiksController) StoreEkCerts(identityRequestChallenge, ekCertBytes []byte, identityChallengePayload taModel.IdentityChallengePayload) error {
	defaultLog.Trace("controllers/certify_host_aiks_controller:StoreEkCerts() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:StoreEkCerts() Leaving")

	fInfo, err := os.Stat(certifyHostAiksController.AikRequestsDirPath)
	if os.IsNotExist(err) || fInfo.Mode().Perm() != 0700 {
		errDir := os.MkdirAll(certifyHostAiksController.AikRequestsDirPath, 0700)
		if errDir != nil {
			return errors.Wrapf(err, "controllers/certify_host_aiks_controller:StoreEkCerts() could not create directory %s", certifyHostAiksController.AikRequestsDirPath)
		}
	}

	idReqFileName := hex.EncodeToString(identityRequestChallenge)
	defaultLog.Debugf("controllers/certify_host_aiks_controller:StoreEkCerts() idReqFileName: %s", idReqFileName)
	optionsFileName := idReqFileName + ".opt"
	// add validation to check if the file exists with permission 0400
	fInfoAikMod, err := os.Stat(certifyHostAiksController.AikRequestsDirPath+idReqFileName)
	if fInfoAikMod != nil && fInfoAikMod.Mode().Perm() != 0400 {
		return errors.Errorf("Invalid file permission on %s", certifyHostAiksController.AikRequestsDirPath+idReqFileName)
	}
	err = ioutil.WriteFile(certifyHostAiksController.AikRequestsDirPath+idReqFileName, identityChallengePayload.IdentityRequest.AikModulus, 0400)
	if err != nil {
		return err
	}

	// add validation to check if the file exists with permission 0400
	fInfoAik, err := os.Stat(certifyHostAiksController.AikRequestsDirPath+optionsFileName)
	if fInfoAik != nil && fInfoAik.Mode().Perm() != 0400 {
		return errors.Errorf("Invalid file permission on %s", certifyHostAiksController.AikRequestsDirPath+optionsFileName)
	}
	err = ioutil.WriteFile(certifyHostAiksController.AikRequestsDirPath+optionsFileName, identityChallengePayload.IdentityRequest.AikName, 0400)
	if err != nil {
		return err
	}

	ekcertFilename := idReqFileName + ".ekcert"
	// add validation to check if the file exists with permission 0400
	fInfoEkCert, err := os.Stat(certifyHostAiksController.AikRequestsDirPath+ekcertFilename)
	if fInfoEkCert != nil && fInfoEkCert.Mode().Perm() != 0400 {
		return errors.Errorf("Invalid file permission on %s", certifyHostAiksController.AikRequestsDirPath+ekcertFilename)
	}
	err = ioutil.WriteFile(certifyHostAiksController.AikRequestsDirPath+ekcertFilename, ekCertBytes, 0400)
	if err != nil {
		return err
	}
	return nil
}

func (certifyHostAiksController *CertifyHostAiksController) GetEkCerts(decryptedIdentityRequestChallenge []byte) (*x509.Certificate, []byte, []byte, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:GetEkCerts() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:GetEkCerts() Leaving")

	fileName := hex.EncodeToString(decryptedIdentityRequestChallenge)
	if _, err := os.Stat(certifyHostAiksController.AikRequestsDirPath + fileName); os.IsNotExist(err) {
		return nil, nil, nil, errors.New("controllers/certify_host_aiks_controller:GetEkCerts() Invalid Challenge response")
	}
	defaultLog.Debugf("ek cert fileName: %s", fileName)
	ekcertFile := certifyHostAiksController.AikRequestsDirPath + fileName + ".ekcert"
	ekCert, err := ioutil.ReadFile(ekcertFile)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "controllers/certify_host_aiks_controller:GetEkCerts() Unable to read file %s", ekcertFile)
	}

	ekx509Cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "controllers/certify_host_aiks_controller:GetEkCerts() Unable to parse certificate")
	}

	optionsFile := certifyHostAiksController.AikRequestsDirPath + fileName + ".opt"
	challengeFile := certifyHostAiksController.AikRequestsDirPath + fileName

	modulus, err := ioutil.ReadFile(challengeFile)
	if err != nil {
		return nil, nil, nil, err
	}

	aikName, err := ioutil.ReadFile(optionsFile)
	if err != nil {
		return nil, nil, nil, err
	}

	return ekx509Cert, modulus, aikName, nil
}

func (certifyHostAiksController *CertifyHostAiksController) IdentityRequestGetChallenge(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson{
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() %s - Error reading request body: %s for request %s", commLogMsg.AppRuntimeErr, string(data), r.URL.Path)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading request body"}
	}
	var identityChallengePayload taModel.IdentityChallengePayload
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&identityChallengePayload)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:identityRequestGetChallenge() %s - Error marshaling json data: %s", commLogMsg.InvalidInputBadEncoding, string(data))
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error marshaling json data"}
	}
	proofReq, status, err := certifyHostAiksController.getIdentityProofRequest(identityChallengePayload)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:identityRequestGetChallenge() Error while getting IdentityProofRequest")
		return nil, status, &commErr.ResourceError{Message: "Error while getting IdentityProofRequest"}
	}

	return proofReq, status, nil
}

func (certifyHostAiksController *CertifyHostAiksController) getIdentityProofRequest(identityChallengePayload taModel.IdentityChallengePayload) (taModel.IdentityProofRequest, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequest() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequest() Leaving")

	privacyca, err := libPrivacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}
	ekCertBytes, err := privacyca.GetEkCert(identityChallengePayload, (*certifyHostAiksController.CertStore)[models.CaCertTypesPrivacyCa.String()].Key)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() unable to get ek cert bytes")
	}

	ekCert, err := x509.ParseCertificate(ekCertBytes)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}
	endorsementCerts := (*certifyHostAiksController.CertStore)[models.CaCertTypesEndorsementCa.String()].Certificates

	defaultLog.Debugf("controllers/certify_host_aiks_controller:getIdentityProofRequest() ekCert Issuer Name :%s", ekCert.Issuer.CommonName)
	var endorsementCertsToVerify x509.Certificate
	for _, cert := range endorsementCerts {
		if cert.Issuer.CommonName == strings.ReplaceAll(ekCert.Issuer.CommonName, "\\x00", "") {
			endorsementCertsToVerify = cert
			break
		}
	}
	if !certifyHostAiksController.isEkCertificateVerifiedByAuthority(ekCert, &endorsementCertsToVerify) && !certifyHostAiksController.isEkCertificateVerifiedByAnyAuthority(ekCert, endorsementCerts) && !certifyHostAiksController.isEkCertRegistered(ekCert) {
		secLog.Errorf("controllers/certify_host_aiks_controller:getIdentityProofRequest() EC is not trusted, Please verify Endorsement Authority certificate is present in EndorsementCA file or ekcert is not registered with hvs")
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() EC is not trusted")
	}

	identityRequestChallenge, err := crypt.GetRandomBytes(32)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	err = certifyHostAiksController.StoreEkCerts(identityRequestChallenge, ekCertBytes, identityChallengePayload)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	privacyca, err = libPrivacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	proofReq, err := privacyca.ProcessIdentityRequest(identityChallengePayload.IdentityRequest, ekCert.PublicKey.(*rsa.PublicKey), identityRequestChallenge)
	if err != nil {
		defaultLog.WithError(err).Error("Unable to generate random bytes for identityRequestChallenge")
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	return proofReq, http.StatusOK, nil
}

func (certifyHostAiksController *CertifyHostAiksController) isEkCertificateVerifiedByAuthority(cert *x509.Certificate, authority *x509.Certificate) bool {
	defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Leaving")
	if authority.Raw == nil {
		return false
	}

	err := cert.CheckSignatureFrom(authority)
	if err != nil {
		defaultLog.Debugf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() %v", err)
		return false
	}

	return true
}

func (certifyHostAiksController *CertifyHostAiksController) IdentityRequestSubmitChallengeResponse(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson{
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defaultLog.Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() %s - Error reading request body: %s for request %s", commLogMsg.AppRuntimeErr, string(data), r.URL.Path)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading request body"}
	}

	var identityChallengePayload taModel.IdentityChallengePayload
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&identityChallengePayload)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() %s - Error marshaling json data: %s", commLogMsg.InvalidInputBadEncoding, string(data))
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error marshaling json data"}
	}

	proofReq, status, err := certifyHostAiksController.getIdentityProofRequestResponse(identityChallengePayload)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Error while getting IdentityProofRequestResponse")
		return nil, status, &commErr.ResourceError{Message: "Error while getting IdentityProofRequestResponse"}
	}

	return proofReq, status, nil

}

func (certifyHostAiksController *CertifyHostAiksController) getIdentityProofRequestResponse(identityChallengePayload taModel.IdentityChallengePayload) (taModel.IdentityProofRequest, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Leaving")

	privacycaTpm2, err := libPrivacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to get new privacyca instance")
	}

	decryptedIdentityRequestChallenge, err := privacycaTpm2.GetEkCert(identityChallengePayload, (*certifyHostAiksController.CertStore)[models.CaCertTypesPrivacyCa.String()].Key)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() unable to get ek cert bytes")
	}
	if _, err := os.Stat(certifyHostAiksController.AikRequestsDirPath); os.IsNotExist(err) {
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() directory %s doesnot exist", certifyHostAiksController.AikRequestsDirPath)
	}

	ekx509Cert, modulus, aikName, err := certifyHostAiksController.GetEkCerts(decryptedIdentityRequestChallenge)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	privacycaTpm2, err = libPrivacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	n := new(big.Int)
	n.SetBytes(modulus)

	aikPubKey := rsa.PublicKey{N: n, E: 65537}
	pcaKey := (*certifyHostAiksController.CertStore)[models.CaCertTypesPrivacyCa.String()].Key
	pcaCert := (*certifyHostAiksController.CertStore)[models.CaCertTypesPrivacyCa.String()].Certificates
	aikCert, err := certifyHostAiksController.CertifyAik(&aikPubKey, aikName, pcaKey.(*rsa.PrivateKey), &pcaCert[0], certifyHostAiksController.AikCertValidity)
	if err != nil {
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to Certify Aik")
	}

	proofReq, err := privacycaTpm2.ProcessIdentityRequest(identityChallengePayload.IdentityRequest, ekx509Cert.PublicKey.(*rsa.PublicKey), aikCert)
	if err != nil {
		defaultLog.WithError(err).Error("")
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Error while generating identityProofRequest")
	}

	return proofReq, http.StatusOK, nil
}

func (certifyHostAiksController *CertifyHostAiksController) CertifyAik(aikPubKey *rsa.PublicKey, aikName []byte, privacycaKey *rsa.PrivateKey, privacycaCert *x509.Certificate, validity int) ([]byte, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:CertifyAik() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:CertifyAik() Leaving")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate serial number")
	}

	clientCRTTemplate := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: privacycaCert.Issuer.CommonName,
		},
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: privacycaCert.Issuer.CommonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(validity, 0, 0),
	}

	extSubjectAltName := pkix.Extension{}
	// Oid "2.5.29.17" is for SubjectAlternativeName extension
	extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
	extSubjectAltName.Critical = false
	extSubjectAltName.Value = aikName
	clientCRTTemplate.Extensions = []pkix.Extension{extSubjectAltName}

	aikCert, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, privacycaCert, aikPubKey, privacycaKey)
	if err != nil {
		return nil, errors.Wrap(err, "Error while Signing and generation Aik Certificate")
	}
	return aikCert, nil
}

func (certifyHostAiksController *CertifyHostAiksController) isEkCertRegistered(cert *x509.Certificate) bool {
	defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertRegistered() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertRegistered() Leaving")
	certDigest, err := crypt.GetCertHashInHex(cert, crypto.SHA384)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error while creating digest for EC")
		return false
	}
	registeredCerts, err := certifyHostAiksController.ECStore.Search(&models.TpmEndorsementFilterCriteria{CertificateDigestEqualTo: certDigest})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error while searching registered EC for issuer %s", cert.Issuer)
		return false
	}
	if len(registeredCerts.TpmEndorsement) == 0 {
		defaultLog.Debugf("There is no EC present for given issuer %s", cert.Issuer)
		return false
	}

	if registeredCerts.TpmEndorsement[0].Revoked {
		defaultLog.Debugf("EC for given issuer %s is revoked", cert.Issuer)
		return false
	}
	return true
}

func (certifyHostAiksController *CertifyHostAiksController) isEkCertificateVerifiedByAnyAuthority(cert *x509.Certificate, certs []x509.Certificate) bool {
	defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAnyAuthority() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAnyAuthority() Leaving")

	for _, authority := range certs {
		if certifyHostAiksController.isEkCertificateVerifiedByAuthority(cert, &authority) {
			return true
		}
	}
	return false
}
