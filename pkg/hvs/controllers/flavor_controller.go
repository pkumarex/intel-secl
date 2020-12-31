/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/antchfx/jsonquery"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	dm "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor"
	fc "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	fConst "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	fm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	fType "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	fu "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	hcType "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type FlavorController struct {
	FStore    domain.FlavorStore
	FGStore   domain.FlavorGroupStore
	HStore    domain.HostStore
	TCStore   domain.TagCertificateStore
	HTManager domain.HostTrustManager
	CertStore *dm.CertificatesStore
	HostCon   HostController
	FTStore   domain.FlavorTemplateStore
	IsExsi    bool
}

var flavorSearchParams = map[string]bool{"id": true, "key": true, "value": true, "flavorgroupId": true, "flavorParts": true}

func NewFlavorController(fs domain.FlavorStore, fgs domain.FlavorGroupStore, hs domain.HostStore, tcs domain.TagCertificateStore, htm domain.HostTrustManager, certStore *dm.CertificatesStore, hcConfig domain.HostControllerConfig, fts domain.FlavorTemplateStore) *FlavorController {
	// certStore should have an entry for Flavor Signing CA
	if _, found := (*certStore)[dm.CertTypesFlavorSigning.String()]; !found {
		defaultLog.Errorf("controllers/flavor_controller:NewFlavorController() %s : Flavor Signing KeyPair not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	var fsKey crypto.PrivateKey
	fsKey = (*certStore)[dm.CertTypesFlavorSigning.String()].Key
	if fsKey == nil {
		defaultLog.Errorf("controllers/flavor_controller:NewFlavorController() %s : Flavor Signing Key not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	hController := HostController{
		HStore:   hs,
		HCConfig: hcConfig,
	}

	return &FlavorController{
		FStore:    fs,
		FGStore:   fgs,
		HStore:    hs,
		TCStore:   tcs,
		HTManager: htm,
		CertStore: certStore,
		HostCon:   hController,
		FTStore:   fts,
	}
}

func (fcon *FlavorController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Create() Leaving")

	flavorCreateReq, err := getFlavorCreateReq(r)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Content-Type") {
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// validate permissions for each flavorPart
	privileges, err := comctx.GetUserPermissions(r)
	if err != nil {
		secLog.Errorf("flavor_controller:Create() %s", commLogMsg.AuthenticationFailed)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Could not get user permissions from http context"}
	}

	var signedFlavors []hvs.SignedFlavor

	if len(flavorCreateReq.FlavorParts) == 0 {
		if !checkValidFlavorPermission(privileges, []string{consts.FlavorCreate}) {
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
		}
	} else {
		for _, fp := range flavorCreateReq.FlavorParts {
			if fp == fc.FlavorPartHostUnique {
				if !checkValidFlavorPermission(privileges, []string{consts.HostUniqueFlavorCreate, consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			} else if fp == fc.FlavorPartSoftware {
				if !checkValidFlavorPermission(privileges, []string{consts.SoftwareFlavorCreate, consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			} else if fp == fc.FlavorPartAssetTag {
				if !checkValidFlavorPermission(privileges, []string{consts.TagFlavorCreate, consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			} else {
				if !checkValidFlavorPermission(privileges, []string{consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			}
		}
	}

	signedFlavors, err = fcon.createFlavors(flavorCreateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Create() Error creating flavors")
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor with same id/label already exists"}
		}
		if strings.Contains(err.Error(), "401") {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Authentication with trust agent failed"}
		}
		if strings.Contains(err.Error(), "403") {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Authorization with trust agent failed"}
		}
		if strings.Contains(err.Error(), "No templates found") {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "No templates found to create flavors"}
		}
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error creating flavors, error connecting to trust agent"}
	}

	signedFlavorCollection := hvs.SignedFlavorCollection{
		SignedFlavors: signedFlavors,
	}
	// Reorder flavors as per request
	if flavorCreateReq.FlavorParts != nil && len(flavorCreateReq.FlavorParts) > 0 {
		signedFlavorCollection = orderFlavorsPerFlavorParts(flavorCreateReq.FlavorParts, signedFlavorCollection)
	}
	secLog.Info("Flavors created successfully")
	return signedFlavorCollection, http.StatusCreated, nil
}

func (fcon *FlavorController) createFlavors(flavorReq dm.FlavorCreateRequest) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:createFlavors() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createFlavors() Leaving")

	var flavorParts []fc.FlavorPart
	var platformFlavor *fType.PlatformFlavor
	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavor)

	if flavorReq.ConnectionString != "" {
		// get flavor from host
		// get host manifest from the host
		defaultLog.Debug("Host connection string given, trying to create flavors from host")
		connectionString, _, err := GenerateConnectionString(flavorReq.ConnectionString,
			fcon.HostCon.HCConfig.Username,
			fcon.HostCon.HCConfig.Password,
			fcon.HostCon.HCStore)

		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Could not generate formatted connection string")
			return nil, errors.Wrap(err, "Error while generating a formatted connection string")
		}
		defaultLog.Debug("Getting manifest from host...")

		hostManifest, err := fcon.getHostManifest(connectionString)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Error getting host manifest")
			return nil, errors.Wrap(err, "Error getting host manifest")
		}

		var flavorTemplates []hvs.FlavorTemplate
		if !strings.EqualFold(hostManifest.HostInfo.OSName, "VMWARE ESXI") {
			defaultLog.Debug("Getting flavor templates...")
			flavorTemplates, err = fcon.findTemplatesToApply(hostManifest)
			if err != nil || len(flavorTemplates) == 0 {
				defaultLog.WithError(err).Error("controllers/flavor_controller:CreateFlavors() No templates found to apply")
				return nil, errors.Wrap(err, "No templates found to create flavors")
			}

			defaultLog.Debug("Matched Flavor templates ", flavorTemplates)
		}

		tagCertificate := hvs.TagCertificate{}
		var tagX509Certificate *x509.Certificate
		tcFilterCriteria := dm.TagCertificateFilterCriteria{
			HardwareUUID: uuid.MustParse(hostManifest.HostInfo.HardwareUUID),
		}
		tagCertificates, err := fcon.TCStore.Search(&tcFilterCriteria)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Error in finding the templates to apply")
			return nil, errors.Wrap(err, "Error getting host manifest")
		}
		if len(tagCertificates) >= 1 {
			tagCertificate = *tagCertificates[0]
			tagX509Certificate, err = x509.ParseCertificate(tagCertificate.Certificate)
			if err != nil {
				defaultLog.Errorf("controllers/flavor_controller: Failed to parse x509.Certificate from tag certificate for host with hardware UUID %s", hostManifest.HostInfo.HardwareUUID)
				return nil, errors.Wrapf(err, "Failed to parse x509.Certificate from tag certificate for host with hardware UUID %s", hostManifest.HostInfo.HardwareUUID)
			}
			defaultLog.Debugf("Tag attribute certificate exists for the host with hardware UUID: %s", hostManifest.HostInfo.HardwareUUID)
		}
		// create a platform flavor with the host manifest information
		defaultLog.Debug("Creating flavor from host manifest using flavor library")
		newPlatformFlavor, err := flavor.NewPlatformFlavorProvider(hostManifest, tagX509Certificate, flavorTemplates)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:createFlavors() Error while creating platform flavor instance from host manifest and tag certificate")
			return nil, errors.Wrap(err, "Error while creating platform flavor instance from host manifest and tag certificate")
		}
		platformFlavor, err = newPlatformFlavor.GetPlatformFlavor()
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:createFlavors() Error while creating platform flavors for host %s", hostManifest.HostInfo.HardwareUUID)
			return nil, errors.Wrapf(err, " Error while creating platform flavors for host %s", hostManifest.HostInfo.HardwareUUID)
		}
		// add all the flavor parts from create request to the list flavor parts to be associated with a flavorgroup
		if len(flavorReq.FlavorParts) >= 1 {
			for _, flavorPart := range flavorReq.FlavorParts {
				flavorParts = append(flavorParts, flavorPart)
			}
		}

	} else if len(flavorReq.FlavorCollection.Flavors) >= 1 || len(flavorReq.SignedFlavorCollection.SignedFlavors) >= 1 {
		defaultLog.Debug("Creating flavors from flavor content")
		flavorSignKey, _, _ := (*fcon.CertStore).GetKeyAndCertificates(dm.CertTypesFlavorSigning.String())

		// create flavors from flavor content
		// TODO: currently checking only the unsigned flavors
		for _, flavor := range flavorReq.FlavorCollection.Flavors {
			// TODO : check if BIOS flavor part name is still accepted, if it is update the flavorpart to PLATFORM
			defaultLog.Debug("Validating flavor meta content for flavor part")
			if err := validateFlavorMetaContent(&flavor.Flavor.Meta); err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor content must be given, invalid flavor meta data")
				return nil, errors.Wrap(err, "Invalid flavor content")
			}
			// get flavor part form the content
			var fp fc.FlavorPart
			if err := (&fp).Parse(flavor.Flavor.Meta.Description[fm.FlavorPart].(string)); err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor part must be given")
				return nil, errors.Wrap(err, "Error parsing flavor part")
			}
			// check if flavor part already exists in flavor-flavorPart map, else sign the flavor and add it to the map
			var platformFlavorUtil fu.PlatformFlavorUtil

			defaultLog.Debug("Signing the flavor content")
			signedFlavor, err := platformFlavorUtil.GetSignedFlavor(&flavor.Flavor, flavorSignKey.(*rsa.PrivateKey))
			if err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting signed flavor from flavor library")
				return nil, errors.Wrap(err, "Error getting signed flavor from flavor library")
			}

			if _, ok := flavorFlavorPartMap[fp]; ok {
				// sign the flavor and add it to the same flavor list
				flavorFlavorPartMap[fp] = append(flavorFlavorPartMap[fp], *signedFlavor)
			} else {
				// add the flavor to the new list
				flavorFlavorPartMap[fp] = []hvs.SignedFlavor{*signedFlavor}
			}
			flavorParts = append(flavorParts, fp)
		}
		if len(flavorFlavorPartMap) == 0 {
			defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor content must be given")
			return nil, errors.New("Valid flavor content must be given")
		}
	}
	var err error
	// add all flavorparts to default flavorgroups if flavorgroup name is not given
	if flavorReq.FlavorgroupNames == nil && len(flavorReq.FlavorParts) == 0 {
		for _, flavorPart := range fc.GetFlavorTypes() {
			flavorParts = append(flavorParts, flavorPart)
		}
	}
	// get the flavorgroup names
	if len(flavorReq.FlavorgroupNames) == 0 {
		flavorReq.FlavorgroupNames = []string{dm.FlavorGroupsAutomatic.String()}
	}
	// check if the flavorgroup is already created, else create flavorgroup
	flavorgroups, err := CreateMissingFlavorgroups(fcon.FGStore, flavorReq.FlavorgroupNames)
	if err != nil {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting flavorgroups")
		return nil, err
	}

	// if platform flavor was retrieved from host, break it into the flavor part flavor map using the flavorgroups
	if platformFlavor != nil {
		flavorFlavorPartMap = fcon.retrieveFlavorCollection(platformFlavor, flavorgroups, flavorParts)
	}

	if flavorFlavorPartMap == nil || len(flavorFlavorPartMap) == 0 {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Cannot create flavors")
		return nil, errors.New("Unable to create Flavors")
	}
	return fcon.addFlavorToFlavorgroup(flavorFlavorPartMap, flavorgroups)
}

func getFlavorCreateReq(r *http.Request) (dm.FlavorCreateRequest, error) {
	defaultLog.Trace("controllers/flavor_controller:getFlavorCreateReq() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getFlavorCreateReq() Leaving")

	var flavorCreateReq dm.FlavorCreateRequest
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		secLog.Error("controllers/flavor_controller:getFlavorCreateReq() Invalid Content-Type")
		return flavorCreateReq, errors.New("Invalid Content-Type")
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavor_controller:getFlavorCreateReq() The request body is not provided")
		return flavorCreateReq, errors.New("The request body is not provided")
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		secLog.Error("controllers/flavor_controller:getFlavorCreateReq() Unable to read the request body")
		return flavorCreateReq, errors.New("Unable to read request body")
	}

	//Restore the request body to it's original state
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&flavorCreateReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_controller:getFlavorCreateReq() %s :  Failed to decode request body as Flavor", commLogMsg.InvalidInputBadEncoding)
		return flavorCreateReq, errors.New("Unable to decode JSON request body")
	}

	defaultLog.Debug("Validating create flavor request")
	err = validateFlavorCreateRequest(flavorCreateReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_controller:CreateFlavors() %s Invalid flavor create criteria", commLogMsg.InvalidInputBadParam)
		return flavorCreateReq, errors.New("Invalid flavor create criteria")
	}
	//Unique flavor parts
	flavorCreateReq.FlavorParts = fc.FilterUniqueFlavorParts(flavorCreateReq.FlavorParts)

	return flavorCreateReq, nil
}

func orderFlavorsPerFlavorParts(parts []fc.FlavorPart, signedFlavorCollection hvs.SignedFlavorCollection) hvs.SignedFlavorCollection {
	signedFlavors := []hvs.SignedFlavor{}
	for _, flavorPart := range parts {
		signedFlavors = append(signedFlavors, signedFlavorCollection.GetFlavors(flavorPart.String())...)
	}
	return hvs.SignedFlavorCollection{
		SignedFlavors: signedFlavors,
	}
}

func (fcon *FlavorController) getHostManifest(cs string) (*hcType.HostManifest, error) {
	defaultLog.Trace("controllers/flavor_controller:getHostManifest() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getHostManifest() Leaving")
	hostConnector, err := fcon.HostCon.HCConfig.HostConnectorProvider.NewHostConnector(cs)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}
	hostManifest, err := hostConnector.GetHostManifest()
	return &hostManifest, err
}

func (fcon *FlavorController) findTemplatesToApply(hostManifest *hcType.HostManifest) ([]hvs.FlavorTemplate, error) {
	defaultLog.Trace("controllers/flavor_controller:findTemplatesToApply() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:findTemplatesToApply() Leaving")
	var filteredTemplates []hvs.FlavorTemplate
	flavorTemplates, err := fcon.FTStore.Search(false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:findTemplatesToApply() Error retrieving all flavor templates")
		return nil, err
	}

	hostManifestBytes, err := json.Marshal(hostManifest)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:findTemplatesToApply() Error Marshalling hostmanifest")
		return nil, err
	}

	hostManifestJson, err := jsonquery.Parse(strings.NewReader(string(hostManifestBytes)))
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:findTemplatesToApply() Error in parsing the host manifest")
		return nil, err
	}

	for _, flavorTemplate := range flavorTemplates {
		conditionEval := true
		for _, condition := range flavorTemplate.Condition {
			expectedData, _ := jsonquery.Query(hostManifestJson, condition)
			if expectedData == nil {
				conditionEval = false
				break
			}
		}
		if conditionEval == true {
			filteredTemplates = append(filteredTemplates, flavorTemplate)
		}
	}

	if len(filteredTemplates) == 0 {
		return nil, errors.New("No templates found")
	}

	return filteredTemplates, nil
}

func (fcon *FlavorController) addFlavorToFlavorgroup(flavorFlavorPartMap map[fc.FlavorPart][]hvs.SignedFlavor, fgs []hvs.FlavorGroup) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Leaving")

	defaultLog.Debug("Adding flavors to flavorgroup")
	var returnSignedFlavors []hvs.SignedFlavor
	// map of flavorgroup to flavor UUID's to create the association
	flavorgroupFlavorMap := make(map[uuid.UUID][]uuid.UUID)
	var flavorgroupsForQueue []hvs.FlavorGroup
	fetchHostData := false
	var fgHostIds []uuid.UUID

	for flavorPart, signedFlavors := range flavorFlavorPartMap {
		defaultLog.Debugf("Creating flavors for fp %s", flavorPart.String())
		for _, signedFlavor := range signedFlavors {
			flavorgroups := []hvs.FlavorGroup{}
			signedFlavorCreated, err := fcon.FStore.Create(&signedFlavor)
			if err != nil {
				defaultLog.WithError(err).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : "+
					"Unable to create flavors of %s flavorPart", flavorPart.String())
				if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
					defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
						"Error cleaning up already existing flavors on flavor creation failure")
				}

				return nil, err
			}
			// if the flavor is created, associate it with an appropriate flavorgroup
			if signedFlavorCreated != nil && signedFlavorCreated.Flavor.Meta.ID.String() != "" {
				// add the created flavor to the list of flavors to be returned
				returnSignedFlavors = append(returnSignedFlavors, *signedFlavorCreated)
				if flavorPart == fc.FlavorPartAssetTag || flavorPart == fc.FlavorPartHostUnique {
					flavorgroup, err := fcon.createFGIfNotExists(dm.FlavorGroupsHostUnique.String())
					if err != nil || flavorgroup.ID == uuid.Nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Error getting host_unique flavorgroup")
						if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
							defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
								"Error cleaning up already existing flavors on flavor creation failure")
						}
						return nil, err
					}
					flavorgroupsForQueue = append(flavorgroupsForQueue, *flavorgroup)
					// get hostId
					var hostHardwareUUID uuid.UUID
					if !reflect.DeepEqual(signedFlavorCreated.Flavor.Meta, fm.Meta{}) &&
						// TODO :
						//!reflect.DeepEqual(signedFlavorCreated.Flavor.Meta.Description, fm.Description{}) &&
						signedFlavorCreated.Flavor.Meta.Description[fm.HardwareUUID] != nil {
						hostHardwareUUID = uuid.MustParse(signedFlavorCreated.Flavor.Meta.Description[fm.HardwareUUID].(string))
					} else {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Hardware UUID must be specified in the flavor document")
						if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
							defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
								"Error cleaning up already existing flavors on flavor creation failure")
						}
						return nil, errors.New("Hardware UUID must be specified in the HOST_UNIQUE flavor")
					}

					hosts, err := fcon.HStore.Search(&dm.HostFilterCriteria{
						HostHardwareId: hostHardwareUUID,
					})
					if len(hosts) == 0 || err != nil {
						defaultLog.Infof("Host with matching hardware UUID not registered")
					}
					for _, host := range hosts {
						// associate host unique flavors such as HOST_UNIQUE and ASSET_TAG with the hosts
						if _, err := fcon.HStore.AddHostUniqueFlavors(host.Id, []uuid.UUID{signedFlavorCreated.Flavor.Meta.ID}); err != nil {
							defaultLog.WithError(err).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : "+
								"Unable to associate %s flavorPart with host id : %v", flavorPart.String(), host.Id)
							return nil, errors.Wrap(err, "Unable to associate flavorPart with host id")
						}
						// add host to the list of host Id's to be added into flavor-verification queue
						fgHostIds = append(fgHostIds, host.Id)
					}
					if flavorPart == fc.FlavorPartAssetTag {
						fetchHostData = true
					}
					flavorgroups = []hvs.FlavorGroup{*flavorgroup}
				} else if flavorPart == fc.FlavorPartSoftware {
					var softwareFgName string
					addToNonSoftwareGroup := false
					if strings.Contains(signedFlavorCreated.Flavor.Meta.Description[fm.Label].(string), fConst.DefaultSoftwareFlavorPrefix) {
						softwareFgName = dm.FlavorGroupsPlatformSoftware.String()
					} else if strings.Contains(signedFlavorCreated.Flavor.Meta.Description[fm.Label].(string), fConst.DefaultWorkloadFlavorPrefix) {
						softwareFgName = dm.FlavorGroupsWorkloadSoftware.String()
					} else {
						addToNonSoftwareGroup = true
					}
					if !addToNonSoftwareGroup {
						flavorgroup, err := fcon.createFGIfNotExists(softwareFgName)
						if err != nil || flavorgroup.ID == uuid.Nil {
							defaultLog.Errorf("controllers/flavor_controller:addFlavorToFlavorgroup() Error getting %v flavorgroup", softwareFgName)
							if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
								defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
									"Error cleaning up already existing flavors on flavor creation failure")
							}
							return nil, err
						}
						flavorgroupsForQueue = append(flavorgroupsForQueue, *flavorgroup)
						flavorgroups = []hvs.FlavorGroup{*flavorgroup}
					} else {
						flavorgroupsForQueue = append(flavorgroupsForQueue, fgs...)
						flavorgroups = fgs
					}
					fetchHostData = true

				} else if flavorPart == fc.FlavorPartPlatform || flavorPart == fc.FlavorPartOs {
					flavorgroups = fgs
					flavorgroupsForQueue = append(flavorgroupsForQueue, flavorgroups...)
				}
			} else {
				defaultLog.Error("controllers/flavor_controller: addFlavorToFlavorgroup(): Unable to create flavors")
				if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
					defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
						"Error cleaning up already existing flavors on flavor creation failure")
				}
				return nil, errors.New("Unable to create flavors")
			}
			for _, flavorgroup := range flavorgroups {
				if _, ok := flavorgroupFlavorMap[flavorgroup.ID]; ok {
					flavorgroupFlavorMap[flavorgroup.ID] = append(flavorgroupFlavorMap[flavorgroup.ID], signedFlavorCreated.Flavor.Meta.ID)
				} else {
					flavorgroupFlavorMap[flavorgroup.ID] = []uuid.UUID{signedFlavorCreated.Flavor.Meta.ID}
				}
			}
		}
	}

	// for each flavorgroup, we have to associate it with flavors
	for fgId, fIds := range flavorgroupFlavorMap {
		_, err := fcon.FGStore.AddFlavors(fgId, fIds)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding flavors to flavorgroup %s", fgId.String())
			if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
				defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
					"Error cleaning up already existing flavors on flavor creation failure")
			}
		}
	}
	// get all the hosts that belong to the same flavor group and add them to flavor-verify queue
	err := fcon.addFlavorgroupHostsToFlavorVerifyQueue(flavorgroupsForQueue, fgHostIds, fetchHostData)
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding hosts to flavor-verify queue")
		if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
			defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
				"Error cleaning up already existing flavors on flavor creation failure")
		}
		return nil, err
	}
	return returnSignedFlavors, nil
}

/*func (fcon *FlavorController) addFlavorToFlavorgroup(flavorFlavorPartMap map[fc.FlavorPart][]hvs.SignedFlavor, fgs []hvs.FlavorGroup) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Leaving")

	defaultLog.Debug("Adding flavors to flavorgroup")
	var returnSignedFlavors []hvs.SignedFlavor
	// map of flavorgroup to flavor UUID's to create the association
	flavorgroupFlavorMap := make(map[uuid.UUID][]uuid.UUID)
	var flavorgroupsForQueue []hvs.FlavorGroup
	fetchHostData := false
	var fgHostIds []uuid.UUID

	for flavorPart, signedFlavors := range flavorFlavorPartMap {
		defaultLog.Debugf("Creating flavors for fp %s", flavorPart.String())
		for _, signedFlavor := range signedFlavors {
			flavorgroups := []hvs.FlavorGroup{}
			signedFlavorCreated, err := fcon.FStore.Create(&signedFlavor)
			if err != nil {
				defaultLog.WithError(err).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : "+
					"Unable to create flavors of %s flavorPart", flavorPart.String())
				if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
					defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
						"Error cleaning up already existing flavors on flavor creation failure")
				}

				return nil, err
			}
			// if the flavor is created, associate it with an appropriate flavorgroup
			if signedFlavorCreated != nil && signedFlavorCreated.Flavor.Meta.ID.String() != "" {
				// add the created flavor to the list of flavors to be returned
				returnSignedFlavors = append(returnSignedFlavors, *signedFlavorCreated)
				if flavorPart == fc.FlavorPartAssetTag || flavorPart == fc.FlavorPartHostUnique {
					flavorgroup, err := fcon.createFGIfNotExists(dm.FlavorGroupsHostUnique.String())
					if err != nil || flavorgroup.ID == uuid.Nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Error getting host_unique flavorgroup")
						if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
							defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
								"Error cleaning up already existing flavors on flavor creation failure")
						}
						return nil, err
					}
					flavorgroupsForQueue = append(flavorgroupsForQueue, *flavorgroup)
					// get hostId
					//To-do
					//!reflect.DeepEqual(signedFlavorCreated.Flavor.Meta.Description, fm.Description{}) &&
					var hostHardwareUUID uuid.UUID
					if !reflect.DeepEqual(signedFlavorCreated.Flavor.Meta, fm.Meta{}) &&
						signedFlavorCreated.Flavor.Meta.Description[fm.HardwareUUID] != nil {
						hostHardwareUUID = signedFlavorCreated.Flavor.Meta.Description[fm.HardwareUUID].(uuid.UUID)
					} else {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() hardware UUID must be specified in the flavor document")
						if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
							defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
								"Error cleaning up already existing flavors on flavor creation failure")
						}
						return nil, errors.New("hardware UUID must be specified in the HOST_UNIQUE flavor")
					}

					hosts, err := fcon.HStore.Search(&dm.HostFilterCriteria{
						HostHardwareId: hostHardwareUUID,
					})
					if len(hosts) == 0 || err != nil {
						defaultLog.Infof("Host with matching hardware UUID not registered")
					}
					for _, host := range hosts {
						// associate host unique flavors such as HOST_UNIQUE and ASSET_TAG with the hosts
						if _, err := fcon.HStore.AddHostUniqueFlavors(host.Id, []uuid.UUID{signedFlavorCreated.Flavor.Meta.ID}); err != nil {
							defaultLog.WithError(err).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : "+
								"Unable to associate %s flavorPart with host id : %v", flavorPart.String(), host.Id)
							return nil, errors.Wrap(err, "Unable to associate flavorPart with host id")
						}
						// add host to the list of host Id's to be added into flavor-verification queue
						fgHostIds = append(fgHostIds, host.Id)
					}
					if flavorPart == fc.FlavorPartAssetTag {
						fetchHostData = true
					}
					flavorgroups = []hvs.FlavorGroup{*flavorgroup}
				} else if flavorPart == fc.FlavorPartSoftware {
					var softwareFgName string
					addToNonSoftwareGroup := false
					if strings.Contains(signedFlavorCreated.Flavor.Meta.Description[fm.Label].(string), fConst.DefaultSoftwareFlavorPrefix) {
						softwareFgName = dm.FlavorGroupsPlatformSoftware.String()
					} else if strings.Contains(signedFlavorCreated.Flavor.Meta.Description[fm.Label].(string), fConst.DefaultWorkloadFlavorPrefix) {
						softwareFgName = dm.FlavorGroupsWorkloadSoftware.String()
					} else {
						addToNonSoftwareGroup = true
					}
					if !addToNonSoftwareGroup {
						flavorgroup, err := fcon.createFGIfNotExists(softwareFgName)
						if err != nil || flavorgroup.ID == uuid.Nil {
							defaultLog.Errorf("controllers/flavor_controller:addFlavorToFlavorgroup() Error getting %v flavorgroup", softwareFgName)
							if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
								defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
									"Error cleaning up already existing flavors on flavor creation failure")
							}
							return nil, err
						}
						flavorgroupsForQueue = append(flavorgroupsForQueue, *flavorgroup)
						flavorgroups = []hvs.FlavorGroup{*flavorgroup}
					} else {
						flavorgroupsForQueue = append(flavorgroupsForQueue, fgs...)
						flavorgroups = fgs
					}
					fetchHostData = true

				} else if flavorPart == fc.FlavorPartPlatform || flavorPart == fc.FlavorPartOs {
					flavorgroups = fgs
					flavorgroupsForQueue = append(flavorgroupsForQueue, flavorgroups...)
				}
			} else {
				defaultLog.Error("controllers/flavor_controller: addFlavorToFlavorgroup(): Unable to create flavors")
				if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
					defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
						"Error cleaning up already existing flavors on flavor creation failure")
				}
				return nil, errors.New("Unable to create flavors")
			}
			for _, flavorgroup := range flavorgroups {
				if _, ok := flavorgroupFlavorMap[flavorgroup.ID]; ok {
					flavorgroupFlavorMap[flavorgroup.ID] = append(flavorgroupFlavorMap[flavorgroup.ID], signedFlavorCreated.Flavor.Meta.ID)
				} else {
					flavorgroupFlavorMap[flavorgroup.ID] = []uuid.UUID{signedFlavorCreated.Flavor.Meta.ID}
				}
			}
		}
	}

	// for each flavorgroup, we have to associate it with flavors
	for fgId, fIds := range flavorgroupFlavorMap {
		_, err := fcon.FGStore.AddFlavors(fgId, fIds)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding flavors to flavorgroup %s", fgId.String())
			if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
				defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
					"Error cleaning up already existing flavors on flavor creation failure")
			}
		}
	}
	// get all the hosts that belong to the same flavor group and add them to flavor-verify queue
	err := fcon.addFlavorgroupHostsToFlavorVerifyQueue(flavorgroupsForQueue, fgHostIds, fetchHostData)
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding hosts to flavor-verify queue")
		if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
			defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
				"Error cleaning up already existing flavors on flavor creation failure")
		}
		return nil, err
	}
	return returnSignedFlavors, nil
}*/

func (fcon FlavorController) addFlavorgroupHostsToFlavorVerifyQueue(fgs []hvs.FlavorGroup, hostIds []uuid.UUID, forceUpdate bool) error {
	defaultLog.Trace("controllers/flavor_controller:addFlavorgroupHostsToFlavorVerifyQueue() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorgroupHostsToFlavorVerifyQueue() Leaving")
	fgHosts := make(map[uuid.UUID]bool)

	// for each flavorgroup, find the hosts that belong to the flavorgroup
	// and add it to the list of host ID's
	for _, fg := range fgs {
		defaultLog.Debugf("Adding hosts that belong to %s flavorgroup", fg.Name)
		if fg.Name == dm.FlavorGroupsHostUnique.String() && len(hostIds) >= 1 {
			for _, hId := range hostIds {
				if _, ok := fgHosts[hId]; !ok {
					fgHosts[hId] = true
				}
			}
		} else {
			hIds, err := fcon.FGStore.SearchHostsByFlavorGroup(fg.ID)
			if err != nil {
				defaultLog.Errorf("controllers/flavor_controller:addFlavorgroupHostsToFlavorVerifyQueue(): Failed to fetch hosts linked to FlavorGroup")
				return err
			}
			for _, hId := range hIds {
				// adding to the list only if not already added
				if _, ok := fgHosts[hId]; !ok {
					fgHosts[hId] = true
				}
			}
		}
	}

	var hostIdsForQueue []uuid.UUID
	for hId := range fgHosts {
		hostIdsForQueue = append(hostIdsForQueue, hId)
	}

	defaultLog.Debugf("Found %v hosts to be added to flavor-verify queue", len(hostIdsForQueue))
	// adding all the host linked to flavorgroup to flavor-verify queue
	if len(hostIdsForQueue) >= 1 {
		err := fcon.HTManager.VerifyHostsAsync(hostIdsForQueue, forceUpdate, false)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Host to Flavor Verify Queue addition failed")
			return err
		}
	}
	return nil
}

func (fcon FlavorController) retrieveFlavorCollection(platformFlavor *fType.PlatformFlavor, fgs []hvs.FlavorGroup, flavorParts []fc.FlavorPart) map[fc.FlavorPart][]hvs.SignedFlavor {
	defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Leaving")

	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavor)
	flavorSignKey := (*fcon.CertStore)[dm.CertTypesFlavorSigning.String()].Key

	if fgs == nil || platformFlavor == nil {
		defaultLog.Error("controllers/flavor_controller:retrieveFlavorCollection() Platform flavor and flavorgroup must be specified")
		return flavorFlavorPartMap
	}

	if len(flavorParts) == 0 {
		flavorParts = append(flavorParts, fc.FlavorPartSoftware)
	}

	for _, flavorPart := range flavorParts {
		unsignedFlavors, err := (*platformFlavor).GetFlavorPartRaw(flavorPart)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error building a flavor for flavor part %s", flavorPart)
			return flavorFlavorPartMap
		}

		signedFlavors, err := fu.PlatformFlavorUtil{}.GetSignedFlavorList(unsignedFlavors, flavorSignKey.(*rsa.PrivateKey))
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error signing flavor %s", flavorPart)
			return flavorFlavorPartMap
		}

		for _, signedFlavor := range signedFlavors {
			if _, ok := flavorFlavorPartMap[flavorPart]; ok {
				flavorFlavorPartMap[flavorPart] = append(flavorFlavorPartMap[flavorPart], signedFlavor)
			} else {
				flavorFlavorPartMap[flavorPart] = []hvs.SignedFlavor{signedFlavor}
			}
		}
	}
	return flavorFlavorPartMap
}

func (fcon *FlavorController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query flavors")

	if err := utils.ValidateQueryParams(r.URL.Query(), flavorSearchParams); err != nil {
		secLog.Errorf("controllers/flavor_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	ids := r.URL.Query()["id"]
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	flavorgroupId := r.URL.Query().Get("flavorgroupId")
	flavorParts := r.URL.Query()["flavorParts"]

	filterCriteria, err := validateFlavorFilterCriteria(key, value, flavorgroupId, ids, flavorParts)
	if err != nil {
		secLog.Errorf("controllers/flavor_controller:Search()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	signedFlavors, err := fcon.FStore.Search(&dm.FlavorVerificationFC{
		FlavorFC: *filterCriteria,
	})
	if err != nil || len(signedFlavors) == 0 {

		signedFlavors, err := fcon.FStore.Search(&dm.FlavorVerificationFC{
			FlavorFC: *filterCriteria,
		})

		if err != nil {
			secLog.WithError(err).Error("controllers/flavor_controller:Search() Flavor get all failed")
			return nil, http.StatusInternalServerError, errors.Errorf("Unable to search Flavors")
		}
		return hvs.SignedFlavorCollection{SignedFlavors: signedFlavors}, http.StatusOK, nil
	}

	secLog.Infof("%s: Return flavor query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hvs.SignedFlavorCollection{SignedFlavors: signedFlavors}, http.StatusOK, nil
}

func (fcon *FlavorController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Delete() Leaving")

	flavorId := uuid.MustParse(mux.Vars(r)["id"])
	signedFlavor, err := fcon.FStore.Retrieve(flavorId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", flavorId).Info(
				"controllers/flavor_controller:Delete()  Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", flavorId).Info(
				"controllers/flavor_controller:Delete() Failed to delete Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
		}
	}

	hostIdsForQueue, err := getHostsAssociatedWithFlavor(fcon.HStore, fcon.FGStore, signedFlavor)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Delete() Failed to retrieve hosts " +
			"associated with flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve hosts " +
			"associated with flavor for trust re-verification"}
	}

	if err := fcon.FStore.Delete(flavorId); err != nil {
		defaultLog.WithError(err).WithField("id", flavorId).Info(
			"controllers/flavor_controller:Delete() failed to delete Flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
	}

	defaultLog.Debugf("Found %v hosts to be added to flavor-verify queue", len(hostIdsForQueue))
	// adding all the host linked to flavor to flavor-verify queue
	if len(hostIdsForQueue) >= 1 {
		err := fcon.HTManager.VerifyHostsAsync(hostIdsForQueue, false, false)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:Delete() Host to Flavor Verify Queue addition failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to re-verify hosts " +
				"associated with deleted Flavor"}
		}
	}
	return nil, http.StatusNoContent, nil
}

func getHostsAssociatedWithFlavor(hStore domain.HostStore, fgStore domain.FlavorGroupStore, flavor *hvs.SignedFlavor) ([]uuid.UUID, error) {
	defaultLog.Trace("controllers/flavor_controller:getHostsAssociatedWithFlavor() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getHostsAssociatedWithFlavor() Leaving")

	id := flavor.Flavor.Meta.ID
	flavorGroups, err := fgStore.Search(&dm.FlavorGroupFilterCriteria{FlavorId: &id})
	if err != nil {
		return nil, errors.Wrapf(err, "controllers/flavor_controller:getHostsAssociatedWithFlavor() Failed to retrieve flavorgroups "+
			"associated with flavor %v for trust re-verification", id)
	}

	var hostIdsForQueue []uuid.UUID
	for _, flavorGroup := range flavorGroups {
		//Host unique flavors are associated with only host_unique flavorgroup and associated with only one host uniquely
		if flavorGroup.Name == dm.FlavorGroupsHostUnique.String() {
			hosts, err := hStore.Search(&dm.HostFilterCriteria{
				HostHardwareId: flavor.Flavor.Meta.Description[fm.HardwareUUID].(uuid.UUID),
			})
			if err != nil {
				return nil, errors.Wrapf(err, "controllers/flavor_controller:getHostsAssociatedWithFlavor() Failed to retrieve hosts "+
					"associated with flavor %v for trust re-verification", id)
			}
			if len(hosts) > 0 {
				hostIdsForQueue = append(hostIdsForQueue, hosts[0].Id)
				break
			}
		}
		hostIds, err := fgStore.SearchHostsByFlavorGroup(flavorGroup.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "controllers/flavor_controller:getHostsAssociatedWithFlavor() Failed to retrieve hosts "+
				"associated with flavorgroup %v for trust re-verification", flavorGroup.ID)
		}
		hostIdsForQueue = append(hostIdsForQueue, hostIds...)
	}
	return hostIdsForQueue, nil
}

func (fcon *FlavorController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	flavor, err := fcon.FStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			flavor, err := fcon.FStore.Retrieve(id)
			if strings.Contains(err.Error(), commErr.RowsNotFound) {
				secLog.WithError(err).WithField("id", id).Info(
					"controllers/flavor_controller:Retrieve() Flavor with given ID does not exist")
				return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
			}
			return flavor, http.StatusOK, nil
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() Failed to retrieve Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor with the given ID"}
		}
	}
	return flavor, http.StatusOK, nil
}

func (fcon *FlavorController) RetrieveEsxiFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	flavor, err := fcon.FStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() failed to retrieve Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor with the given ID"}
		}
	}
	return flavor, http.StatusOK, nil
}

func validateFlavorFilterCriteria(key, value, flavorgroupId string, ids, flavorParts []string) (*dm.FlavorFilterCriteria, error) {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Leaving")

	filterCriteria := dm.FlavorFilterCriteria{}
	var err error
	if len(ids) > 0 {
		var fIds []uuid.UUID
		for _, fId := range ids {
			parsedId, err := uuid.Parse(fId)
			if err != nil {
				return nil, errors.New("Invalid UUID format of the flavor identifier")
			}
			fIds = append(fIds, parsedId)
		}
		filterCriteria.Ids = fIds
	}
	if key != "" && value != "" {
		if err = validation.ValidateStrings([]string{key, value}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for filter Key and Value must be specified")
		}
		filterCriteria.Key = key
		filterCriteria.Value = value
	}
	if flavorgroupId != "" {
		filterCriteria.FlavorgroupID, err = uuid.Parse(flavorgroupId)
		if err != nil {
			return nil, errors.New("Invalid UUID format of flavorgroup identifier")
		}
	}
	if len(flavorParts) > 0 {
		filterCriteria.FlavorParts, err = parseFlavorParts(flavorParts)
		if err != nil {
			return nil, errors.Wrap(err, "Valid contents of filter flavor_parts must be given")
		}
	}

	return &filterCriteria, nil
}

func validateFlavorCreateRequest(criteria dm.FlavorCreateRequest) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Leaving")

	if criteria.ConnectionString == "" && len(criteria.FlavorCollection.Flavors) == 0 && len(criteria.SignedFlavorCollection.SignedFlavors) == 0 {
		secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Valid host connection string or flavor content must be given")
		return errors.New("Valid host connection string or flavor content must be given")
	}
	if criteria.ConnectionString != "" {
		err := utils.ValidateConnectionString(criteria.ConnectionString)
		if err != nil {
			secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Invalid host connection string")
			return errors.New("Invalid host connection string")
		}
	}
	if len(criteria.FlavorgroupNames) != 0 {
		for _, flavorgroup := range criteria.FlavorgroupNames {
			if flavorgroup == "" {
				return errors.New("Valid Flavorgroup Names must be specified, empty name is not allowed")
			}
		}
		err := validation.ValidateStrings(criteria.FlavorgroupNames)
		if err != nil {
			return errors.New("Invalid flavorgroup name given as a flavor create criteria")
		}
	}
	if len(criteria.FlavorParts) > 0 {
		var flavorParts []string
		var err error
		for _, fp := range criteria.FlavorParts {
			flavorParts = append(flavorParts, fp.String())
		}
		criteria.FlavorParts, err = parseFlavorParts(flavorParts)
		if err != nil {
			return errors.New("Valid flavor parts must be given as a flavor create criteria")
		}
	}

	return nil
}

// func validateFlavorCreateRequestFC(criteria dm.FlavorCreateRequest) error {
// 	defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Entering")
// 	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Leaving")

// 	if criteria.ConnectionString == "" && len(criteria.FlavorCollection.Flavors) == 0 && len(criteria.SignedFlavorCollection.SignedFlavors) == 0 {
// 		secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Valid host connection string or flavor content must be given")
// 		return errors.New("Valid host connection string or flavor content must be given")
// 	}
// 	if criteria.ConnectionString != "" {
// 		err := utils.ValidateConnectionString(criteria.ConnectionString)
// 		if err != nil {
// 			secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Invalid host connection string")
// 			return errors.New("Invalid host connection string")
// 		}
// 	}
// 	if len(criteria.FlavorgroupNames) != 0 {
// 		for _, flavorgroup := range criteria.FlavorgroupNames {
// 			if flavorgroup == "" {
// 				return errors.New("Valid Flavorgroup Names must be specified, empty name is not allowed")
// 			}
// 		}
// 		err := validation.ValidateStrings(criteria.FlavorgroupNames)
// 		if err != nil {
// 			return errors.New("Invalid flavorgroup name given as a flavor create criteria")
// 		}
// 	}
// 	if len(criteria.FlavorParts) > 0 {
// 		var flavorParts []string
// 		var err error
// 		for _, fp := range criteria.FlavorParts {
// 			flavorParts = append(flavorParts, fp.String())
// 		}
// 		criteria.FlavorParts, err = parseFlavorParts(flavorParts)
// 		if err != nil {
// 			return errors.New("Valid flavor parts must be given as a flavor create criteria")
// 		}
// 	}

// 	return nil
// }

func validateFlavorMetaContent(meta *fm.Meta) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorMetaContent() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorMetaContent() Leaving")
	//To-Do
	//reflect.DeepEqual(meta.Description, fm.Description{}) ||
	if meta == nil || meta.Description[fm.Label].(string) == "" {
		return errors.New("Invalid flavor meta content : flavor label missing")
	}
	var fp fc.FlavorPart
	if err := (&fp).Parse(meta.Description[fm.FlavorPart].(string)); err != nil {
		return errors.New("Flavor Part must be ASSET_TAG, SOFTWARE, HOST_UNIQUE, PLATFORM or OS")
	}
	return nil
}

func parseFlavorParts(flavorParts []string) ([]fc.FlavorPart, error) {
	defaultLog.Trace("controllers/flavor_controller:parseFlavorParts() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:parseFlavorParts() Leaving")
	// validate if the given flavor parts are valid and convert it to FlavorPart type
	var validFlavorParts []fc.FlavorPart
	for _, flavorPart := range flavorParts {
		var fp fc.FlavorPart
		if err := (&fp).Parse(flavorPart); err != nil {
			return nil, errors.New("Valid FlavorPart as a filter must be specified")
		}
		validFlavorParts = append(validFlavorParts, fp)
	}
	return validFlavorParts, nil
}

func (fcon *FlavorController) createFGIfNotExists(fgName string) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("controllers/flavor_controller:createFGIfNotExists() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createFGIfNotExists() Leaving")

	if fgName == "" {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Flavorgroup name cannot be nil")
		return nil, errors.New("Flavorgroup name cannot be nil")
	}

	flavorgroups, err := fcon.FGStore.Search(&dm.FlavorGroupFilterCriteria{
		NameEqualTo: fgName,
	})
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Error searching for flavorgroup with name %s", fgName)
		return nil, errors.Wrapf(err, "Error searching for flavorgroup with name %s", fgName)
	}

	if len(flavorgroups) > 0 && flavorgroups[0].ID != uuid.Nil {
		return &flavorgroups[0], nil
	}
	// if flavorgroup of the given name doesn't exist, create a new one
	var fg hvs.FlavorGroup
	var policies []hvs.FlavorMatchPolicy
	if fgName == dm.FlavorGroupsWorkloadSoftware.String() || fgName == dm.FlavorGroupsPlatformSoftware.String() {
		policies = append(policies, hvs.NewFlavorMatchPolicy(fc.FlavorPartSoftware, hvs.NewMatchPolicy(hvs.MatchTypeAnyOf, hvs.FlavorRequired)))
		fg = hvs.FlavorGroup{
			Name:          fgName,
			MatchPolicies: policies,
		}
	} else if fgName == dm.FlavorGroupsHostUnique.String() {
		fg = hvs.FlavorGroup{
			Name: fgName,
		}
	} else {
		fg = utils.CreateFlavorGroupByName(fgName)
	}

	flavorgroup, err := fcon.FGStore.Create(&fg)
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Flavor creation failed while creating flavorgroup"+
			"with name %s", fgName)
		return nil, errors.Wrap(err, "Unable to create flavorgroup")
	}
	return flavorgroup, nil
}

func (fcon *FlavorController) createCleanUp(fgFlavorMap map[uuid.UUID][]uuid.UUID) error {
	defaultLog.Trace("controllers/flavor_controller:createCleanUp() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createCleanUp() Leaving")
	if len(fgFlavorMap) <= 0 {
		return nil
	}
	defaultLog.Info("Error occurred while creating flavors. So, cleaning up already created flavors....")
	// deleting all the flavor created
	for _, fIds := range fgFlavorMap {
		for _, fId := range fIds {
			if err := fcon.FStore.Delete(fId); err != nil {
				defaultLog.Info("Failed to delete flavor and clean up when create flavors errored out")
				return errors.New("Failed to delete Flavor and clean up when create flavors errored out")
			}
		}
	}
	return nil
}

func checkValidFlavorPermission(privileges []ct.PermissionInfo, requiredPermission []string) bool {
	reqPermissions := ct.PermissionInfo{Service: consts.ServiceName, Rules: requiredPermission}
	_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
		true)
	if !foundMatchingPermission {
		secLog.Errorf("router/handlers:permissionsHandler() %s Insufficient privileges to access /v2/hvs/flavors", commLogMsg.UnauthorizedAccess)
		return false
	}
	return true
}
