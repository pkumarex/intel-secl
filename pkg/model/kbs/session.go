/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

type KeyTransferSession struct {
	SWK            []byte `json:"swk"`
	SessionId      string `json:"sessionid"`
	ClientCertHash string `json:"clientcerthash"`
	Stmlabel       string `json:"stmlabel"`
}

type ChallengeRequest struct {
	Challenge     string        `json:"challenge"`
	ChallengeType string        `json:"challenge_type"`
	Faults        []Fault       `json:"faults"`
	Link          ChallengeLink `json:"link"`
	Operation     string        `json:"operation"`
	Status        string        `json:"status"`
}

type Fault struct {
	Type string `json:"type"`
}

type ChallengeLink struct {
	ChallengeReply ChallengeReplyToNode `json:"challenge-replyto"`
}

type ChallengeReplyToNode struct {
	Href   string `json:"href"`
	Method string `json:"method"`
}

type QuoteVerifyAttributes struct {
	Status                         string `json:"Status"`
	Message                        string `json:"Message"`
	ChallengeKeyType               string `json:"ChallengeKeyType"`
	ChallengeRsaPublicKey          string `json:"ChallengeRsaPublicKey"`
	EnclaveIssuer                  string `json:"EnclaveIssuer"`
	EnclaveIssuerProductID         string `json:"EnclaveIssuerProdID"`
	EnclaveIssuerExtendedProductID string `json:"EnclaveIssuerExtProdID"`
	EnclaveMeasurement             string `json:"EnclaveMeasurement"`
	ConfigSvn                      string `json:"ConfigSvn"`
	IsvSvn                         string `json:"IsvSvn"`
	ConfigID                       string `json:"ConfigId"`
	TCBLevel                       string `json:"TcbLevel"`
}

type QuoteVerifyResponse struct {
	Created []QuoteVerifyAttributes `json:"created,omitempty"`
}

type SessionResponseAttributes struct {
	SessionData Data   `json:"data"`
	Operation   string `json:"operation"`
	Status      string `json:"status"`
}

type Data struct {
	SWK           []byte `json:"swk,omitempty"`
	AlgorithmType string `json:"type,omitempty"`
}

type SessionManagementAttributes struct {
	ChallengeType    string `json:"challenge_type"`
	Challenge        string `json:"challenge"`
	Quote            string `json:"quote"`
}
