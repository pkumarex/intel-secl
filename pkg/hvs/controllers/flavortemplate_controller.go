/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	dm "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/pkg/errors"
)

type FlavorTemplateCreationController struct {
	Store domain.FlavorTemplateStore
}

func (ftc FlavorTemplateCreationController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("controllers/flavortemplate_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Create() Leaving")

	flavorTemplateReq, err := getFlavorTemplateCreateReq(r)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Content-Type") {
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	//Store this template into database.
	flavorTemplate, err := ftc.Store.Create(&flavorTemplateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Create() Error creation flavor template")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	//TODO: Create Flavor(s) from this template.
	//Check flavor group name is given in request.
	//True
	//	Create flavor group, in given name and associate all created flavors with that flavor group.
	//	Associate created flavor group with this flavor template.
	//Else
	//	Add created flavors to default flavor group. and associate flavor template to default flavorgroup.

	//Flavorgroup association with flavor template

	return flavorTemplate, http.StatusOK, nil
}

func (ftc FlavorTemplateCreationController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Leaving")

	templateID := uuid.MustParse(mux.Vars(r)["id"])
	includeDeleted := r.URL.Query().Get("include_deleted")
	defaultLog.Debugf("controllers/flavortemplate_controller:Retrieve() ID : ", templateID)

	included, err := validateQueryParameter(includeDeleted)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Invalid query parameter given")
		return false, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid query parameter given"}
	}

	flavorTemplate, err := ftc.Store.Retrieve(templateID, included)

	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() FlavorTeamplate with given ID is deleted")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorTeamplate with given ID is deleted"}
		} else {
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() failed to retrieve FlavorTeamplate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorTeamplate with the given ID"}
		}
	}
	return flavorTemplate, http.StatusOK, nil
}

func validateQueryParameter(includeDeleted string) (bool, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:validateQueryParameter() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:validateQueryParameter() Leaving")

	var included bool
	if len(includeDeleted) > 0 && includeDeleted != "" {
		if strings.EqualFold(includeDeleted, "true") {
			included = true
		} else if strings.EqualFold(includeDeleted, "false") {
			included = false
		} else {
			defaultLog.Error("controllers/flavortemplate_controller:validateQueryParameter() Invalid query parameter given")
			return false, errors.New("Invalid query parameter given")
		}
	}
	return included, nil
}

func (ftc FlavorTemplateCreationController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Search() Leaving")

	includeDeleted := r.URL.Query().Get("include_deleted")

	included, err := validateQueryParameter(includeDeleted)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Invalid query parameter given")
		return false, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid query parameter given"}
	}

	//call store function to retrieve all available templates from DB.
	flavorTemplates, err := ftc.Store.Search(included)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Error retrieving all flavor templates")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	return flavorTemplates, http.StatusOK, nil
}

func (ftc FlavorTemplateCreationController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Delete() Leaving")

	templateId := uuid.MustParse(mux.Vars(r)["id"])
	defaultLog.Debugf("controllers/flavortemplate_controller:Delete() ID : ", templateId)

	//call store function to delete template from DB.
	if err := ftc.Store.Delete(templateId); err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Delete() Error delete flavor templates")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	return nil, http.StatusNoContent, nil

}

func getFlavorTemplateCreateReq(r *http.Request) (dm.FlavorTemplate, error) {

	defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Leaving")

	var CreateFlavorTemplateReq dm.FlavorTemplate
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		secLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Invalid Content-Type")
		return CreateFlavorTemplateReq, errors.New("Invalid Content-Type")
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() The request body is not provided")
		return CreateFlavorTemplateReq, errors.New("The request body is not provided")
	}

	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&CreateFlavorTemplateReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() %s :  Failed to decode request body as Flavor", commLogMsg.InvalidInputBadEncoding)
		return CreateFlavorTemplateReq, errors.New("Unable to decode JSON request body")
	}

	if CreateFlavorTemplateReq.ID != uuid.Nil {
		secLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Invalid flavor template request given ID should be NIL")
		return CreateFlavorTemplateReq, errors.New("Invalid flavor template requested")
	}

	defaultLog.Debug("Validating create flavor request")
	err = validateFlavorTemplateCreateRequest(CreateFlavorTemplateReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() %s Invalid flavor template create criteria", commLogMsg.InvalidInputBadParam)
		return CreateFlavorTemplateReq, errors.New("Invalid flavor create criteria")
	}

	//Initiate flavor part creation and once done store.

	return CreateFlavorTemplateReq, nil
}

func validateFlavorTemplateCreateRequest(dm.FlavorTemplate) error {
	defaultLog.Trace("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Leaving")
	//Add template validation.
	return nil
}
