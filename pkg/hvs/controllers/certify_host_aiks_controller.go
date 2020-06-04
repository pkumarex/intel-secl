/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
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
}

func (certifyHostAiksController *CertifyHostAiksController) IdentityRequestGetChallenge(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() Leaving")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), r.URL.Path)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading request body"}
	}
	var identityChallengePayload taModel.IdentityChallengePayload
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&identityChallengePayload)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:identityRequestGetChallenge() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error marshaling json data"}
	}
	proofReq, err := getIdentityProofRequest(identityChallengePayload)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:identityRequestGetChallenge() Error while getting IdentityProofRequest")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while getting IdentityProofRequest"}
	}

	return proofReq, http.StatusOK, nil

}

func getPrivacyCAKey()(interface{}, error){
	privacyCAKeyBytes, err := ioutil.ReadFile(constants.KeyPath)
	if err != nil{
		return nil, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getPrivacyCAKey() Unable to read %s", constants.KeyPath)
	}

	block, _ := pem.Decode(privacyCAKeyBytes)
	if block == nil{
		return nil, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getPrivacyCAKey() Unable to decode with pem privacyca bytes")
	}

	privacycaKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil{
		return nil, errors.Wrap(err, "controllers/certify_host_aiks_controller:getPrivacyCAKey() Unable to parse privacyca key")
	}
	return privacycaKey, nil
}

func getIdentityProofRequest(identityChallengePayload taModel.IdentityChallengePayload) (taModel.IdentityProofRequest, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequest() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequest() Leaving")

	privacycaKey, err := getPrivacyCAKey()
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() Unable to get privacyca key in bytes")
	}
	privacycaTpm2, err := privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() Unable to get new privacyca instance")
	}
	ekCertBytes, err := privacycaTpm2.GetEkCert(identityChallengePayload, privacycaKey)
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() unable to get ek cert bytes")
	}

	ekCert, err :=  x509.ParseCertificate(ekCertBytes)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	endorsementCerts, err := getEndorsementCerts()
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() Error while getting endorsement certs")
	}

	defaultLog.Debugf("controllers/certify_host_aiks_controller:getIdentityProofRequest() ekCert Issuer Name :%s", ekCert.Issuer.CommonName)
	endorsementCertsToVerify := endorsementCerts[strings.ReplaceAll(ekCert.Issuer.String(), "\\x00","")]


	if !isEkCertificateVerifiedByAuthority(ekCert, endorsementCertsToVerify) {
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() EC is not trusted")
	}

	identityRequestChallenge, err := crypt.GetRandomBytes(32)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	if _, err := os.Stat(constants.AikRequestsDir); os.IsNotExist(err) {
		errDir := os.MkdirAll(constants.AikRequestsDir, 0700)
		if errDir != nil {
			return taModel.IdentityProofRequest{}, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() could not create directory %s", constants.AikRequestsDir)
		}
	}

	idReqFileName := hex.EncodeToString(identityRequestChallenge)
	defaultLog.Debugf("controllers/certify_host_aiks_controller:getIdentityProofRequest() idReqFileName: %s", idReqFileName)
	optionsFileName := idReqFileName + ".opt"
	err = ioutil.WriteFile(constants.AikRequestsDir + idReqFileName, identityChallengePayload.IdentityRequest.AikModulus, 0400)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	err = ioutil.WriteFile(constants.AikRequestsDir + optionsFileName, identityChallengePayload.IdentityRequest.AikName, 0400)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	ekcertFilename := idReqFileName + ".ekcert"
	err = ioutil.WriteFile(constants.AikRequestsDir + ekcertFilename, ekCertBytes, 0400)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	privacycaTpm2, err = privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	proofReq, err := privacycaTpm2.ProcessIdentityRequest(identityChallengePayload.IdentityRequest, ekCert.PublicKey.(*rsa.PublicKey), identityRequestChallenge)
	if err != nil{
		defaultLog.WithError(err).Error("Unable to generate random bytes for identityRequestChallenge")
		return taModel.IdentityProofRequest{}, err
	}

	return proofReq, nil
}

func getEndorsementCerts() (map[string]x509.Certificate, error){
	defaultLog.Trace("controllers/certify_host_aiks_controller:getEndorsementCerts() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getEndorsementCerts() Leaving")

	endorsementCerts := make(map[string]x509.Certificate)
	endorsementCABytes, err := ioutil.ReadFile(constants.EndorsementCAFile)
	if err != nil{
		return nil, err
	}

	block, rest := pem.Decode(endorsementCABytes)
	if block == nil {
		return nil, errors.New("Unable to decode pem bytes")
	}
	ekCertAuth, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err,"Failed to parse certificate 1")
	}
	endorsementCerts[ekCertAuth.Issuer.CommonName] = *ekCertAuth
	if rest == nil {
		return endorsementCerts, nil
	}

	for ;len(rest) > 1;{
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		ekCertAuth, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			defaultLog.WithError(err).Warn("controllers/certify_host_aiks_controller:getEndorsementCerts() Failed to parse certificate")
			continue
		}
		defaultLog.Debugf("controllers/certify_host_aiks_controller:getEndorsementCerts() Issuer :%s", ekCertAuth.Subject.String())
		endorsementCerts[ekCertAuth.Subject.String()] = *ekCertAuth
	}
	return endorsementCerts, nil
}

func isEkCertificateVerifiedByAuthority(cert *x509.Certificate, authority x509.Certificate) bool{
	defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Leaving")

	rsaPublicKey := authority.PublicKey.(*rsa.PublicKey)
	sigAlg := cert.SignatureAlgorithm
	switch sigAlg {
	case x509.SHA1WithRSA:
		h := sha1.New()
		h.Write(cert.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA1, digest, cert.Signature)

		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	case x509.SHA256WithRSA:
		h := sha256.New()
		h.Write(cert.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, cert.Signature)

		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	case x509.SHA384WithRSA:
		h := sha512.New384()
		h.Write(cert.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA384, digest, cert.Signature)

		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	default:
		defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, unsupported signature algorithm")
		return false
		break
	}

	return true
}

//TODO after implementation of TpmEndoresment database layer
/*func isEkCertificateRegistered() bool{
}*/

func (certifyHostAiksController *CertifyHostAiksController) IdentityRequestSubmitChallengeResponse(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Leaving")

		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), r.URL.Path)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading request body"}
		}

		var identityChallengePayload taModel.IdentityChallengePayload
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&identityChallengePayload)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error marshaling json data"}
		}

		proofReq, err := getIdentityProofRequestResponse(identityChallengePayload)
		if err != nil {
			defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Error while getting IdentityProofRequestResponse")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while getting IdentityProofRequestResponse"}
		}

		return proofReq, http.StatusOK, nil

}

func getIdentityProofRequestResponse(identityChallengePayload taModel.IdentityChallengePayload) (taModel.IdentityProofRequest, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Leaving")

	privacycaKey, err := getPrivacyCAKey()
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() Unable to get privacyca key in bytes")
	}

	privacyCACertBytes, err := ioutil.ReadFile(constants.CertPath)
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrapf(err, "Unable to read %s", constants.CertPath)
	}

	block, _ := pem.Decode(privacyCACertBytes)

	privacycaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil{
		defaultLog.WithError(err).Error("Unable to parse privacyca cert")
		return taModel.IdentityProofRequest{}, err
	}

	privacycaTpm2, err := privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to get new privacyca instance")
	}

	decryptedIdentityRequestChallenge, err := privacycaTpm2.GetEkCert(identityChallengePayload, privacycaKey)
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() unable to get ek cert bytes")
	}
	if _, err := os.Stat(constants.AikRequestsDir); os.IsNotExist(err) {
		errDir := os.MkdirAll(constants.AikRequestsDir, 0600)
		if errDir != nil {
			return taModel.IdentityProofRequest{}, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() could not create directory %s", constants.AikRequestsDir)
		}
	}

	fileName := hex.EncodeToString(decryptedIdentityRequestChallenge)
	if _, err := os.Stat(constants.AikRequestsDir + fileName); os.IsNotExist(err) {
		return taModel.IdentityProofRequest{}, errors.New("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Invalid Challenge response")
	}
	defaultLog.Debugf("fileName: %s", fileName)
	ekcertFile := constants.AikRequestsDir + fileName + ".ekcert"
	ekCert, err := ioutil.ReadFile(ekcertFile)
	if err != nil {
		return taModel.IdentityProofRequest{}, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to read file %s", ekcertFile)
	}

	ekx509Cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to parse certificate")
	}

	optionsFile := constants.AikRequestsDir + fileName + ".opt"
	challengeFile := constants.AikRequestsDir + fileName

	modulus, err := ioutil.ReadFile(challengeFile)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	aikName, err := ioutil.ReadFile(optionsFile)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	privacycaTpm2, err = privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, err
	}

	n := new(big.Int)
	n.SetBytes(modulus)

	aikPubKey := rsa.PublicKey{N: n, E: 65537}

	//TODO make PrivacyCA_ValidityDays as configurable??
	aikCert, err := certifyAik(&aikPubKey, aikName, privacycaKey.(*rsa.PrivateKey), privacycaCert, constants.AIKCertValidity)
	if err != nil{
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to Certify Aik")
	}

	//AES CBC Encryption fails with data that is not divisible aes.BlockSize, Adding padding to make the length of payload multiple of aes.Blocksize
	padding := aes.BlockSize - len(aikCert)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	withPadding := append(aikCert, padtext...)

	proofReq, err := privacycaTpm2.ProcessIdentityRequest(identityChallengePayload.IdentityRequest, ekx509Cert.PublicKey.(*rsa.PublicKey), withPadding)
	if err != nil{
		defaultLog.WithError(err).Error("")
		return taModel.IdentityProofRequest{}, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Error while generating identityProofRequest")
	}

	return proofReq, nil
}

func certifyAik(aikPubKey *rsa.PublicKey, aikName []byte, privacycaKey *rsa.PrivateKey, privacycaCert *x509.Certificate, validity int) ([]byte, error)  {
	defaultLog.Trace("controllers/certify_host_aiks_controller:certifyAik() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:certifyAik() Leaving")

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
		Subject:      pkix.Name{
			CommonName: "",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(validity, 0, 0),
	}

	extSubjectAltName := pkix.Extension{}
	// Oid "2.5.29.17" is for SubjectAlternativeName extension
	extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
	extSubjectAltName.Critical = false
	extSubjectAltName.Value = aikName
	clientCRTTemplate.Extensions = []pkix.Extension{extSubjectAltName}

	aikCert, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, privacycaCert, aikPubKey, privacycaKey)
	if err != nil{
		return nil, errors.Wrap(err, "Error while Signing and generation Aik Certificate")
	}
	return aikCert, nil
}
