/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keytransfer"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/session"
	commConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type SessionController struct {
	config           *config.Configuration
	trustedCaCertDir string
}

func NewSessionController(kc *config.Configuration, caCertDir string) *SessionController {
	return &SessionController{config: kc,
		trustedCaCertDir: caCertDir,
	}
}

func (sc *SessionController) Create(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/session_controller:Create() Entering")
	defer defaultLog.Trace("controllers/session_controller:Create() Leaving")

	if request.Header.Get("Content-Type") != commConstants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/session_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var sessionRequest kbs.SessionManagementAttributes

	// Decode the incoming json data to note struct
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&sessionRequest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/session_controller:Create() %s : Failed to decode request body as SessionManagementAttributes", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	err = validateSessionCreateRequest(sessionRequest)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/session_controller:Create() Invalid create request")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid create request"}
	}

	keyInfo := keytransfer.GetKeyInfo()
	sessionObj := keyInfo.GetSessionObj(sessionRequest.Challenge)

	if reflect.DeepEqual(sessionObj, kbs.KeyTransferSession{}) {
		defaultLog.WithError(err).Error("controllers/session_controller:Create() no session object found.")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "no session object found"}
	}
	responseAttributes, err := session.VerifyQuote(sessionRequest.Quote, sc.config, sc.trustedCaCertDir)
	if err != nil || responseAttributes == nil {
		secLog.WithError(err).Error("controllers/session_controller:Create() Remote attestation for new session failed")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Remote attestation for new session failed"}
	}

	keyInfo.SessionResponseMap[sessionRequest.Challenge] = *responseAttributes

	swkKey, err := session.SessionCreateSwk()
	if err != nil {
		secLog.Error("controllers/session_controller:Create() Error in getting SWK key")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in getting SWK key"}
	}

	sessionObj.SWK = swkKey
	keyInfo.SessionMap[sessionRequest.Challenge] = sessionObj

	var respAttr kbs.SessionResponseAttributes
	if responseAttributes.ChallengeKeyType == constants.CRYPTOALG_RSA {
		wrappedKey, err := session.SessionWrapSwkWithRSAKey(responseAttributes.ChallengeKeyType, responseAttributes.ChallengeRsaPublicKey, sessionObj.SWK)
		if err != nil {
			secLog.Error("controllers/session_controller:Create() Unable to wrap the swk with rsa key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in wrapping SWK key with RSA key"}

		}
		respAttr.SessionData.SWK = wrappedKey
		if sessionRequest.ChallengeType == constants.SWAlgorithmType {
			respAttr.SessionData.AlgorithmType = constants.SWAlgorithmType
		} else {
			respAttr.SessionData.AlgorithmType = constants.SGXAlgorithmType
		}
		respAttr.Operation = constants.SessionOperation
		respAttr.Status = constants.SuccessStatus
	} else {
		secLog.Error("controllers/session_controller:Create() Currently only RSA key support is available")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Currently only RSA key support is available"}
	}

	sessionIDStr := fmt.Sprintf("%s:%s", sessionRequest.ChallengeType, sessionRequest.Challenge)
	responseWriter.Header().Add("Session-Id", sessionIDStr)

	secLog.WithField("Session-Id", sessionIDStr).Infof("controllers/session_controller:Create(): Successfully created session: %s", request.RemoteAddr)

	return respAttr, http.StatusCreated, nil
}

func validateSessionCreateRequest(sessionRequest kbs.SessionManagementAttributes) error {
	defaultLog.Trace("controllers/session_controller:validateSessionCreateRequest() Entering")
	defer defaultLog.Trace("controllers/session_controller:validateSessionCreateRequest() Leaving")

	if sessionRequest.ChallengeType == "" || sessionRequest.Challenge == "" || sessionRequest.Quote == "" {
		return errors.New("challenge_type/challenge/quote parameters are missing")
	}

	if sessionRequest.ChallengeType != constants.DefaultSWLabel && sessionRequest.ChallengeType != constants.DefaultSGXLabel {
		return errors.New("challenge_type parameter is not correct.")
	}

	if err := validation.ValidateBase64String(sessionRequest.Challenge); err != nil {
		return errors.New("Challenge is not a base64 string")
	}
	return nil
}
