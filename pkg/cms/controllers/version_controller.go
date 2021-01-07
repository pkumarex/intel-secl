/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/version"
	"net/http"
)

type VersionController struct {
}

func (v VersionController) GetVersion() http.HandlerFunc {
	log.Trace("resource/version:getVersion() Entering")
	defer log.Trace("resource/version:getVersion() Leaving")

	return func(w http.ResponseWriter, r *http.Request) {
		verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
		log.Debugf("resource/version:getVersion() CMS version : %v", verStr)
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(verStr))
		if err != nil {
			log.WithError(err).Error("Could not write version to response")
		}
	}
}
