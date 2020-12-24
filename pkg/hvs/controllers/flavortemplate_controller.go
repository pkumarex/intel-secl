/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/xeipuuv/gojsonschema"
)

type FlavorTemplateController struct {
	Store domain.FlavorTemplateStore
}

func (ftc FlavorTemplateController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

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

	return flavorTemplate, http.StatusOK, nil
}

func (ftc FlavorTemplateController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Leaving")

	templateID := uuid.MustParse(mux.Vars(r)["id"])
	defaultLog.Debugf("controllers/flavortemplate_controller:Retrieve() ID : %s", templateID)

	flavorTemplate, err := ftc.Store.Retrieve(templateID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() Flavor template with given ID does not exist or has been deleted")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor template with given ID does not exist or has been deleted"}
		} else {
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() failed to retrieve FlavorTemplate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorTemplate with the given ID"}
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

func (ftc FlavorTemplateController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
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

func (ftc FlavorTemplateController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Delete() Leaving")

	templateId := uuid.MustParse(mux.Vars(r)["id"])
	defaultLog.Debugf("controllers/flavortemplate_controller:Delete() ID : %s", templateId)

	//call store function to delete template from DB.
	if err := ftc.Store.Delete(templateId); err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Delete() Error delete flavor templates")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	return nil, http.StatusNoContent, nil

}

func getFlavorTemplateCreateReq(r *http.Request) (hvs.FlavorTemplate, error) {

	defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Leaving")

	var CreateFlavorTemplateReq hvs.FlavorTemplate
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		secLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Invalid Content-Type")
		return CreateFlavorTemplateReq, errors.New("Invalid Content-Type")
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() The request body is not provided")
		return CreateFlavorTemplateReq, errors.New("The request body is not provided")
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		secLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to read the request body")
		return CreateFlavorTemplateReq, errors.New("Unable to read request body")
	}

	//TODO : Add schema validation here.

	//Restore the request body to it's original state
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&CreateFlavorTemplateReq)

	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() %s :  Failed to decode request body as Flavor", commLogMsg.InvalidInputBadEncoding)
		return CreateFlavorTemplateReq, errors.New("Unable to decode JSON request body")
	}

	if CreateFlavorTemplateReq.ID != uuid.Nil {
		secLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Invalid flavor template request given ID should be NIL")
		return CreateFlavorTemplateReq, errors.New("Invalid flavor template requested")
	}

	defaultLog.Debug("Validating create flavor request")
	err, errMsg := validateFlavorTemplateCreateRequest(CreateFlavorTemplateReq, string(body))
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() %s Invalid flavor template create criteria", commLogMsg.InvalidInputBadParam)
		return CreateFlavorTemplateReq, errors.New(errMsg)
	}

	//Initiate flavor part creation and once done store.

	return CreateFlavorTemplateReq, nil
}

func validateFlavorTemplateCreateRequest(FlvrTemp hvs.FlavorTemplate, template string) (error, string) {
	defaultLog.Trace("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Leaving")
	// Check whether the template is adhering to the schema
	schemaLoader := gojsonschema.NewSchemaLoader()

	definitionsSchemaJson, err := readJson(consts.CommonDefinitionsSchema)
	if err != nil {
		return errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to read the file"+consts.CommonDefinitionsSchema), "Unable to read the schema"
	}

	definitionsSchema := gojsonschema.NewStringLoader(definitionsSchemaJson)
	templateSchemaJson, err := readJson(consts.FlavorTemplateSchema)
	if err != nil {
		return errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to read the file"+consts.FlavorTemplateSchema), "Unable to read the Schema"
	}
	FlvrTemplateSchema := gojsonschema.NewStringLoader(templateSchemaJson)
	schemaLoader.AddSchemas(definitionsSchema)

	schema, err := schemaLoader.Compile(FlvrTemplateSchema)
	if err != nil {
		return errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to compile the schemas"), "Unable to Validate the template"
	}

	documentLoader := gojsonschema.NewStringLoader(template)

	result, err := schema.Validate(documentLoader)
	if err != nil {
		return errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to validate the template"), "Unable to Validate the template"
	}

	var errorMsg string
	if !result.Valid() {
		for _, desc := range result.Errors() {
			errorMsg = errorMsg + fmt.Sprintf("- %s\n", desc)
		}
		return errors.New("The provided template is not valid" + errorMsg), errorMsg
	}

	defaultLog.Info("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() The provided template is valid")
	//Check whether each pcr index is associated with not more than one bank.

	pcrMap := make(map[*hvs.FlavorPart][]hvs.PCR)
	Flavors := []*hvs.FlavorPart{FlvrTemp.FlavorParts.Platform, FlvrTemp.FlavorParts.OS, FlvrTemp.FlavorParts.HostUnique, FlvrTemp.FlavorParts.Software}
	for _, flavor := range Flavors {
		if flavor != nil {
			if _, ok := pcrMap[flavor]; !ok {
				var pcrs []hvs.PCR
				for _, pcrRule := range flavor.PcrRules {
					pcrs = append(pcrs, pcrRule.Pcr)
				}
				pcrMap[flavor] = pcrs
			}
		}
	}

	for _, pcrList := range pcrMap {
		temp := make(map[int]bool)
		for _, pcr := range pcrList {
			if _, ok := temp[pcr.Index]; !ok {
				temp[pcr.Index] = true
			} else {
				return errors.New("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Template has duplicate banks for same PCR index"), "Template has duplicate banks for same PCR index"
			}
		}
	}

	return nil, ""
}

func readJson(jsonFilePath string) (string, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:readJson() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:readJson() Leaving")
	byteValue, err := ioutil.ReadFile(jsonFilePath)
	if err != nil {
		return "", errors.Wrap(err, "controllers/flavortemplate_controller:readJson() unable to read file"+jsonFilePath)
	}
	return string(byteValue), nil
}
