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

	"github.com/antchfx/jsonquery"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/xeipuuv/gojsonschema"
)

type FlavorTemplateController struct {
	Store                   domain.FlavorTemplateStore
	CommonDefinitionsSchema string
	FlavorTemplateSchema    string
}
type ErrorMessage struct {
	Message string
}

// NewFlavorTemplateController This method is used to initialize the flavorTemplateController
func NewFlavorTemplateController(store domain.FlavorTemplateStore, commonDefinitionsSchema, flavorTemplateSchema string) *FlavorTemplateController {
	return &FlavorTemplateController{
		Store:                   store,
		CommonDefinitionsSchema: commonDefinitionsSchema,
		FlavorTemplateSchema:    flavorTemplateSchema,
	}
}

type unsupportedMediaError ErrorMessage

type badRequestError ErrorMessage

func (e unsupportedMediaError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

func (e badRequestError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

// Create This method is used to create the flavor template and store it in the database
func (ftc *FlavorTemplateController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Create() Leaving")

	flavorTemplateReq, err := ftc.getFlavorTemplateCreateReq(r)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Create() Failed to complete create flavor template")
		switch errorType := err.(type) {
		case *unsupportedMediaError:
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: errorType.Message}
		case *badRequestError:
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: errorType.Message}
		default:
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
		}
	}

	//Store this template into database.
	flavorTemplate, err := ftc.Store.Create(&flavorTemplateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Create() Failed to create flavor template")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create flavor template"}
	}

	return flavorTemplate, http.StatusCreated, nil
}

// Retrieve This method is used to retrieve a flavor template
func (ftc *FlavorTemplateController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Retrieve() Leaving")

	templateID := uuid.MustParse(mux.Vars(r)["id"])

	flavorTemplate, err := ftc.Store.Retrieve(templateID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() Flavor template with given ID does not exist or has been deleted")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor template with given ID does not exist or has been deleted"}
		} else {
			secLog.WithError(err).WithField("id", templateID).Info(
				"controllers/flavortemplate_controller:Retrieve() Failed to retrieve FlavorTemplate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorTemplate with the given ID"}
		}
	}
	return flavorTemplate, http.StatusOK, nil
}

// isIncludeDeleted This method is used to return boolean value of query parameter
func isIncludeDeleted(includeDeleted string) (bool, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:isIncludeDeleted() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:isIncludeDeleted() Leaving")

	if includeDeleted != "" {
		switch includeDeleted {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, errors.New("controllers/flavortemplate_controller:isIncludeDeleted() Invalid query parameter given")
		}
	}
	return false, nil
}

// Search This method is used to retrieve all the flavor templates
func (ftc *FlavorTemplateController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Search() Leaving")

	includeDeleted := r.URL.Query().Get("include_deleted")

	isIncludeDeleted, err := isIncludeDeleted(includeDeleted)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Invalid query parameter given")
		return false, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid query parameter given"}
	}

	//call store function to retrieve all available templates from DB.
	flavorTemplates, err := ftc.Store.Search(isIncludeDeleted)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Error retrieving all flavor templates")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error retrieving all flavor templates"}
	}

	return flavorTemplates, http.StatusOK, nil
}

// Delete This method is used to delete a flavor template
func (ftc *FlavorTemplateController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:Delete() Leaving")

	templateID := uuid.MustParse(mux.Vars(r)["id"])

	//call store function to delete template from DB.
	if err := ftc.Store.Delete(templateID); err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Delete() Flavor template with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor template with given ID does not exist or has been deleted"}
		}
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Delete() Failed to delete flavor template with given ID")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete flavor template with given ID"}
	}

	return nil, http.StatusNoContent, nil
}

// getFlavorTemplateCreateReq This method is used to get the body content of Flavor Template Create Request
func (ftc *FlavorTemplateController) getFlavorTemplateCreateReq(r *http.Request) (hvs.FlavorTemplate, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Leaving")

	var createFlavorTemplateReq hvs.FlavorTemplate
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		defaultLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Invalid Content-Type")
		return createFlavorTemplateReq, &unsupportedMediaError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		defaultLog.Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() The request body is not provided")
		return createFlavorTemplateReq, &badRequestError{Message: "The request body is not provided"}
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to read request body")
		return createFlavorTemplateReq, &badRequestError{Message: "Unable to read request body"}
	}

	//Restore the request body to it's original state
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&createFlavorTemplateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to decode request body")
		return createFlavorTemplateReq, &badRequestError{Message: "Unable to decode request body"}
	}

	if createFlavorTemplateReq.ID != uuid.Nil {
		template, err := ftc.Store.Retrieve(createFlavorTemplateReq.ID)
		if err != nil {
			if strings.Contains(err.Error(), commErr.RowsNotFound) {
				defaultLog.Debug("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Flavor template with given ID is not exists,procceed with template creation")
			} else {
				defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Failed to retrieve flavor template")
				return hvs.FlavorTemplate{}, errors.New("Failed to validate flavor template ID")
			}
		}
		if template != nil || strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to create flavor template, template with given template ID already exists or has been deleted")
			return hvs.FlavorTemplate{}, &badRequestError{Message: "FlavorTemplate with given template ID already exists or has been deleted"}
		}
	}

	defaultLog.Debug("Validating create flavor request")
	errMsg, err := ftc.validateFlavorTemplateCreateRequest(createFlavorTemplateReq, string(body))
	if err != nil {
		return createFlavorTemplateReq, &badRequestError{Message: errMsg}
	}

	if len(createFlavorTemplateReq.Condition) == 0 {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:getFlavorTemplateCreateReq() Unable to create flavor template, empty condition field provided")
		return hvs.FlavorTemplate{}, &badRequestError{Message: "Unable to create flavor template, empty condition field provided"}
	}

	return createFlavorTemplateReq, nil
}

// validateFlavorTemplateCreateRequest This method is used to validate the flavor template
func (ftc *FlavorTemplateController) validateFlavorTemplateCreateRequest(FlvrTemp hvs.FlavorTemplate, template string) (string, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Leaving")
	// Check whether the template is adhering to the schema
	schemaLoader := gojsonschema.NewSchemaLoader()

	definitionsSchemaJSON, err := readJSON(ftc.CommonDefinitionsSchema)
	if err != nil {
		return "Unable to read the schema", errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to read the file"+consts.CommonDefinitionsSchema)
	}

	definitionsSchema := gojsonschema.NewStringLoader(definitionsSchemaJSON)
	templateSchemaJSON, err := readJSON(ftc.FlavorTemplateSchema)
	if err != nil {
		return "Unable to read the schema", errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to read the file"+consts.FlavorTemplateSchema)
	}
	flvrTemplateSchema := gojsonschema.NewStringLoader(templateSchemaJSON)
	schemaLoader.AddSchemas(definitionsSchema)

	schema, err := schemaLoader.Compile(flvrTemplateSchema)
	if err != nil {
		return "Unable to Validate the template", errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to compile the schemas")
	}

	documentLoader := gojsonschema.NewStringLoader(template)

	result, err := schema.Validate(documentLoader)
	if err != nil {
		return "Unable to Validate the template", errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to validate the template")
	}

	var errorMsg string
	if !result.Valid() {
		for _, desc := range result.Errors() {
			errorMsg = errorMsg + fmt.Sprintf("- %s\n", desc)
		}
		return errorMsg, errors.New("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() The provided template is not valid" + errorMsg)
	}

	defaultLog.Info("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() The provided template is valid")

	//Validation the syntax of the conditions
	tempDoc, err := jsonquery.Parse(strings.NewReader("{}"))
	if err != nil {
		return "", errors.Wrap(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Unable to parse json query")
	}

	for _, condition := range FlvrTemp.Condition {
		_, err := jsonquery.Query(tempDoc, condition)
		if err != nil {
			return "Invalid syntax in condition statement", errors.Wrapf(err, "controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Invalid syntax in condition : %s", condition)
		}
	}

	//Check whether each pcr index is associated with not more than one bank.
	pcrMap := make(map[*hvs.FlavorPart][]hvs.PCR)
	flavors := []*hvs.FlavorPart{FlvrTemp.FlavorParts.Platform, FlvrTemp.FlavorParts.OS, FlvrTemp.FlavorParts.HostUnique, FlvrTemp.FlavorParts.Software}
	for _, flavor := range flavors {
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
				return "Template has duplicate banks for same PCR index", errors.New("controllers/flavortemplate_controller:validateFlavorTemplateCreateRequest() Template has duplicate banks for same PCR index")
			}
		}
	}

	return "", nil
}

// readJSON This method is used to read the json file
func readJSON(jsonFilePath string) (string, error) {
	defaultLog.Trace("controllers/flavortemplate_controller:readJSON() Entering")
	defer defaultLog.Trace("controllers/flavortemplate_controller:readJSON() Leaving")
	byteValue, err := ioutil.ReadFile(jsonFilePath)
	if err != nil {
		return "", errors.Wrap(err, "controllers/flavortemplate_controller:readJSON() unable to read file"+jsonFilePath)
	}
	return string(byteValue), nil
}
