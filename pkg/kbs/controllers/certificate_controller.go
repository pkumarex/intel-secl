/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type CertificateController struct {
	store domain.CertificateStore
}

func NewCertificateController(cs domain.CertificateStore) *CertificateController {
	return &CertificateController{store: cs}
}

var certificateSearchParams = map[string]bool{"subjectEqualTo": true, "subjectContains": true, "issuerEqualTo": true, "issuerContains": true,
	"validOn": true, "validBefore": true, "validAfter": true}

//Import : Function to store the provided certificate in directory
func (cc CertificateController) Import(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certificate_controller:Import() Entering")
	defer defaultLog.Trace("controllers/certificate_controller:Import() Leaving")

	certBytes, status, err := getCertificate(request)
	if err != nil {
		return nil, status, err
	}

	cert := &kbs.Certificate{
		Certificate: certBytes,
	}
	createdCert, err := cc.store.Create(cert)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/certificate_controller:Import() Certificate save failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to save certificate"}
	}

	secLog.WithField("Id", createdCert.ID).Infof("controllers/certificate_controller:Import() %s: Certificate imported by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	return createdCert, http.StatusCreated, nil
}

//Retrieve : Function to retrieve certificate
func (cc CertificateController) Retrieve(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certificate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/certificate_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	key, err := cc.store.Retrieve(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/certificate_controller:Retrieve() Certificate with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Certificate with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/certificate_controller:Retrieve() Certificate retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve certificate"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/certificate_controller:Retrieve() Certificate retrieved by: %s", request.RemoteAddr)
	return key, http.StatusOK, nil
}

//Delete : Function to delete certificate
func (cc CertificateController) Delete(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certificate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/certificate_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	err := cc.store.Delete(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/certificate_controller:Delete() Certificate with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Certificate with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/certificate_controller:Delete() Certificate delete failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete certificate"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/certificate_controller:Delete() Certificate deleted by: %s", request.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

//Search : Function used to search certificates based on query parameter
func (cc CertificateController) Search(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certificate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/certificate_controller:Search() Leaving")

	// get the CertificateFilterCriteria
	criteria, err := getCertificateFilterCriteria(request.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certificate_controller:Search() %s : Invalid filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// retrieve the certificates which matches with parameters requested
	certificates, err := cc.store.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/certificate_controller:Search() Certificates search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search certificates"}
	}

	secLog.Infof("controllers/certificate_controller:Search() %s: Certificates searched by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return certificates, http.StatusOK, nil
}

//getCertificate checks for pem formatted certificate in the Import request and returns a valid Certificate
func getCertificate(request *http.Request) ([]byte, int, error) {
	defaultLog.Trace("controllers/certificate_controller:getCertificate() Entering")
	defer defaultLog.Trace("controllers/certificate_controller:getCertificate() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypePemFile {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/certificate_controller:getCertificate() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	bytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certificate_controller:getCertificate() %s : Unable to read request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to read request body"}
	}

	_, err = crypt.GetCertFromPem(bytes)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certificate_controller:getCertificate() %s : Validation failed for certificate", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	return bytes, http.StatusOK, nil
}

//getCertificateFilterCriteria checks for set filter params in the Search request and returns a valid CertificateFilterCriteria
func getCertificateFilterCriteria(params url.Values) (*models.CertificateFilterCriteria, error) {
	defaultLog.Trace("controllers/certificate_controller:getCertificateFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/certificate_controller:getCertificateFilterCriteria() Leaving")

	criteria := models.CertificateFilterCriteria{}
	if err := utils.ValidateQueryParams(params, certificateSearchParams); err != nil {
		return nil, err
	}

	// subjectEqualTo
	if param := strings.TrimSpace(params.Get("subjectEqualTo")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectEqualTo must be specified")
		}
		criteria.SubjectEqualTo = param
	}

	// subjectContains
	if param := strings.TrimSpace(params.Get("subjectContains")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectContains must be specified")
		}
		criteria.SubjectContains = param
	}

	// issuerEqualTo
	if param := strings.TrimSpace(params.Get("issuerEqualTo")); param != "" {
		if err := validation.ValidateIssuer(param); err == nil {
			criteria.IssuerEqualTo = param
		} else {
			return nil, errors.New("Valid contents for issuerEqualTo must be specified")
		}
	}

	// issuerContains
	if param := strings.TrimSpace(params.Get("issuerContains")); param != "" {
		if err := validation.ValidateIssuer(param); err == nil {
			criteria.IssuerContains = param
		} else {
			return nil, errors.New("Valid contents for issuerContains must be specified")
		}
	}

	// validOn
	if param := strings.TrimSpace(params.Get("validOn")); param != "" {
		pTime, err := time.Parse(time.RFC3339, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DDThh:mm:ssZ) for validOn must be specified")
		}
		criteria.ValidOn = pTime
	}

	// validBefore
	if param := strings.TrimSpace(params.Get("validBefore")); param != "" {
		pTime, err := time.Parse(time.RFC3339, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DDThh:mm:ssZ) for validBefore must be specified")
		}
		criteria.ValidBefore = pTime
	}

	// validAfter
	if param := strings.TrimSpace(params.Get("validAfter")); param != "" {
		pTime, err := time.Parse(time.RFC3339, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DDThh:mm:ssZ) for validAfter must be specified")
		}
		criteria.ValidAfter = pTime
	}

	return &criteria, nil
}
