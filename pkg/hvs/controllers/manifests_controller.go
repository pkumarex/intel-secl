/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	fm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	dm "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	"net/http"
)

type ManifestsController struct {
	FlavorStore domain.FlavorStore
}

func NewManifestsController(fs domain.FlavorStore) *ManifestsController {
	return &ManifestsController{
		FlavorStore: fs,
	}
}

func (controller ManifestsController) GetManifest(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/manifests_controller:GetManifest() Entering")
	defer defaultLog.Trace("controllers/manifests_controller:GetManifest() Leaving")

	ids := r.URL.Query()["id"]
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	filterCriteria, err := validateFlavorFilterCriteria(key, value, "", ids, nil)
	if err != nil {
		secLog.Errorf("controllers/manifests_controller:GetManifest()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	signedFlavors, err := controller.FlavorStore.Search(&dm.FlavorVerificationFC{
		FlavorFC: *filterCriteria,
	})
	if err != nil {
			defaultLog.WithError(err).Errorf("controllers/manifests_controller:"+
				"GetManifest() %s : Failed to search flavor from store", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search flavor from store"}
	}

	if signedFlavors == nil || len(signedFlavors) == 0 {
		secLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Flavor with given details does not exist", commLogMsg.InvalidInputBadParam)
		return "", http.StatusNotFound, &commErr.ResourceError{"Flavor with given details does not exist"}
	}

	var fmc util.FlavorToManifestConverter
	if signedFlavors[0].Flavor.Meta.Description[fm.FlavorPart].(string) == string(common.FlavorPartSoftware) {
		manifest := fmc.GetManifestFromFlavor(signedFlavors[0].Flavor)
		return manifest, http.StatusOK, nil
	} else {
		secLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Flavor associated with the provided id is not a SOFTWARE flavor", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor associated with the provided id is not " +
			"a SOFTWARE flavor"}
	}
}
