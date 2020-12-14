/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	consts "github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"io/ioutil"
	"net/http"
	"regexp"

	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

type JwtCertificateController struct {
}

func (controller JwtCertificateController) GetJwtCertificate(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to getJwtCertificate")
	defer defaultLog.Trace("getJwtCertificate return")

	tokenCertificate, err := ioutil.ReadFile(consts.TokenSignCertFile)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	re := regexp.MustCompile(`\r?\n`)
	err = validation.ValidatePemEncodedKey(re.ReplaceAllString(string(tokenCertificate), ""))

	if err != nil {
		secLog.Errorf(commLogMsg.UnauthorizedAccess, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Invalid jwt certificate"}
	}
	secLog.Info(commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(tokenCertificate), http.StatusOK, nil
}
