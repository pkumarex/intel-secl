/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "github.com/intel-secl/intel-secl/v3/pkg/model/kbs"

// Session request payload
// swagger:parameters SessionManagementAttributes
type SessionManagementAttributes struct {
	// in:body
	Body kbs.SessionManagementAttributes
}

// Session response payload
// swagger:parameters SessionResponseAttributes
type SessionResponseAttributes struct {
	// in:body
	Body kbs.SessionResponseAttributes
}

// ---

// swagger:operation POST /session Session CreateSession
// ---
//
// description: |
//   Creates a session. TLS-Mutual authentication happens between KBS and SKC-Library, hence skc-client certificate and root-ca certificate needs to be provided in the request.
//
//   The serialized SessionManagementAttributes Go struct object represents the content of the request body.
//
//    | Attribute          | Description |
//    |--------------------|-------------|
//    | challenge_type     | String to identify Security Technology Module(STM) label, e.g. "SGX" or "SW". |
//    | challenge          | Base64-encoded unique ID shared by KBS. |
//    | quote              | Base64-encoded string containing SGX attributes and public key certificate. Quote can be retrieved by printing it in the KBS/SQVS logs. |
//
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/SessionManagementAttributes"
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: Successfully created the session.
//     headers:
//       Session-Id:
//         type: string
//         description: Mapping of challenge and challenge-type.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SessionResponseAttributes"
//   '400':
//     description: Invalid session create request
//   '401':
//     description: Unauthorized request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/session
// x-sample-call-input: |
//  {
//      "challenge_type": "SGX",
//      "challenge": "MTRjZmNlZDEtMDNlZS00YTY4LThiNTAtNmQ0NTY0MjNiMDc4",
//      "quote": "AQAAAAAAAAB7EwAAAQAAAAEAAAADAAAAAAEAANwGAAAtLS0tLUJFR0lOI...."
//  }
// x-sample-call-output: |
//  {
//      "data": {
//              "swk": "sOCGP84HrADhs8VAmVrYA25w2yQEdMZMLS3il6g2fY0xDucCvRJWapmETaz7Au8t/zDkgVpT9StR6qpscxkTTkk0hE8tD4Lk8ArQ3SBp6a+kOf5Qwj30P/Zsv1WejhoVI/k+PFoMeCDxpqSG9mSKTAYLqFQtnnJGYOIWaIHHn6PARDEvVMFSMD3uqdqPwyx9cx+rt9n8oIcdraYEfpUWzv4uVaDOQj0I/+8WjFL8JgGOdl0n91eo3WGUHFgEjvBNeWdrwvvEMp6GusId4gIuascjpqFrGzjDSuXaLcY00lZIqe9PlyqHMSJg5Q1/QBvz7X4E2iPMU20EoxlOI2QPyg==",
//              "type": "AES256-GCM"
//      },
//      "operation": "establish session key",
//      "status": "success"
//  }
