/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "github.com/intel-secl/intel-secl/v3/pkg/model/kbs"

type KeyResponses []kbs.KeyResponse

// Key request payload
// swagger:parameters KeyRequest
type KeyRequest struct {
	// in:body
	Body kbs.KeyRequest
}

// Key response payload
// swagger:parameters KeyResponse
type KeyResponse struct {
	// in:body
	Body kbs.KeyResponse
}

// KeyCollection response payload
// swagger:parameters KeyCollection
type KeyCollection struct {
	// in:body
	Body KeyResponses
}

// KeyTransfer response payload
// swagger:parameters KeyTransferAttributes
type KeyTransferAttributes struct {
	// in:body
	Body kbs.KeyTransferAttributes
}

// ---

// swagger:operation POST /keys Keys CreateKey
// ---
//
// description: |
//   Creates or Registers a key.
//
//   The serialized KeyRequest Go struct object represents the content of the request body.
//
//    | Attribute          | Description |
//    |--------------------|-------------|
//    | key_information    | A json object having all the required information about a key. |
//    | transfer_policy_id | Unique identifier of the transfer policy to apply to this key. |
//    | label              | String to attach optionally a text description to the key, e.g. "US Nginx key". |
//    | usage              | String to attach optionally a usage criteria for the key, e.g. "Country:US,State:CA". |
//
//   The serialized KeyInformation Go struct object represents the content of the key_information field.
//
//    | Attribute   | Description |
//    |-------------|-------------|
//    | algorithm   | Encryption algorithm used to create or register key. Supported algorithms are AES, RSA and EC. |
//    | key_length  | Key length used to create key. Supported key lengths are 128,192,256 bits for AES and 2048,3072,4096,7680,15360 bits for RSA. |
//    | curve_type  | Elliptic curve used to create key. Supported curves are secp256r1, secp384r1 and secp521r1. |
//    | key_string  | Base64 encoded private key to be registered. Supported only if key is created locally. |
//    | kmip_key_id | Unique KMIP identifier of key to be registered. Supported only if key is created on KMIP server. |
//
// x-permissions: keys:create,keys:register
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
//    "$ref": "#/definitions/KeyRequest"
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
//     description: Successfully created or registered the key.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponse"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys
// x-sample-call-input: |
//    {
//        "key_information": {
//            "algorithm": "AES",
//            "key_length": 256
//        },
//    }
// x-sample-call-output: |
//    {
//        "key_information": {
//            "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//            "algorithm": "AES",
//            "key_length": 256
//        }
//        "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9",
//        "transfer_link": "https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//        "created_at": "2020-09-23T11:16:26.738467277Z"
//    }

// ---

// swagger:operation GET /keys/{id} Keys RetrieveKey
// ---
//
// description: |
//   Retrieves a key.
//   Returns - The serialized KeyResponse Go struct object that was retrieved.
// x-permissions: keys:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the key.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponse"
//   '404':
//     description: Key record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e
// x-sample-call-output: |
//    {
//        "key_information": {
//            "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//            "algorithm": "AES",
//            "key_length": 256
//        }
//        "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9",
//        "transfer_link": "https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//        "created_at": "2020-09-23T11:16:26.738467277Z"
//    }

// ---

// swagger:operation POST /keys/{id}/transfer Keys TransferKey
// ---
//
// description: |
//   Transfers a key.
//   Returns - The serialized KeyTransferAttributes Go struct object that was retrieved.
// x-permissions: keys:transfer
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - text/plain
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - text/plain
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully transferred the key.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferAttributes"
//   '404':
//     description: Key record not found
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer
// x-sample-call-input: |
//    -----BEGIN PUBLIC KEY-----
//    MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwMKVKgQq1oef5rWfIPBp
//    nP5wuwB1FX30h51OJbPhqneSMZYEFmxgX2CYsMgNWyZe3jgsIAkKQcgIKJjPVaQG
//    YPVfCcNJgX6FV51ob1ViQJgsPwkDaoZHAARawlKfWt3VvWp71AxOPqBh+Hk6abag
//    ouGQoMEuZA1lTxyM7U8kt/nJEOotW74FEjp4b6g31TRHYyptw4BVY45mjlqgNv+Z
//    s5RDc2xweWB+wJ2XM1TJtYnanmW0cb6YN6W1FaOeiqnKzxNaRG4AsX5FcKzZ3n4m
//    Y/Fi6QZ7TgVbCknRC9Ni8JU8o5hihYszjMNuDLp9IHZDhl9sjpH3LkvfYesU6O7p
//    vvtn3IsFg7zBUs9yLQO1PMGChnobtDIbp4RfpVWwHB4zFYv0II6XVgmCcze8Ks40
//    wSN0XysccIs0C2USdLvIqO85HXRfbmKhncCxHIPBzKZgbX5xbW6YawH1OmhgIw+o
//    9wZnxYW3O42sBLOr3DDworCA5u+BUpWjWdzyZTycs28jAgMBAAE=
//    -----END PUBLIC KEY-----
// x-sample-call-output: |
//    {
//        "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//        "payload": "F+nUVyejh2Cp0wkLFvqNkhBydtnKY8v5eJ5zbl9gHoPbqvjwuSafx4LwnHOT6DJDqa8LO5ufVyLqqXVfyAdf88s1VnKLCE0Udbn8Zjnq4CHnR2KqDPWTauYLnuYJH2lVGf4Ke4mTcvOfBO9YRTop0WzfTBSuEFKrAsE67ERogtCvD7hf5LhJ2sxv0ej48uZ5KLHRVAzbWMttRZXbL10xTC+dZM9SIAWg2s0aq7Mb49h2rcaI307e3GQgsXhbopwSTC7L7Sy1RYUf4XvHl+/XMmVmvKWjOFIfOXTg8cA+COTBjzOQXVJiXF/xv5/idny0sOeyebFfnxfj7ZXJhqT8pYtiyRm0kzU35jtFTpJR8+aMkOjI/4KdbM6zoY+7JiRD2A0VNEAvQzEoKnY2H9/fIRlkYLtjCI/n5CSPg5Ap0wghqZAmmCeaOH48D0NgjpVQPhc/OQHq/k0HRUXvmUgQe/D4T3WIUdJCctSBGsjIn3WrusH+cb5eaof5Aqq7NT4W",
//        "algorithm": "AES",
//        "key_length": 256,
//        "created_at": "2020-09-23T11:16:26.738467277Z"
//    }

// ---

// swagger:operation DELETE /keys/{id} Keys DeleteKey
// ---
//
// description: |
//   Deletes a key.
// x-permissions: keys:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the key.
//   '404':
//     description: Key record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e

// ---

// swagger:operation GET /keys Keys SearchKey
// ---
//
// description: |
//   Searches for keys.
//   Returns - The collection of serialized KeyResponse Go struct objects.
// x-permissions: keys:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: algorithm
//   description: Key algorithm.
//   in: query
//   type: string
//   required: false
//   enum: [AES, RSA, EC, aes, rsa, ec]
// - name: keyLength
//   description: Key length.
//   in: query
//   type: integer
//   required: false
//   enum: [128, 192, 256, 2048, 3072, 4096, 7680, 15360]
// - name: curveType
//   description: Elliptic Curve name.
//   in: query
//   type: string
//   required: false
//   enum: [secp256r1, secp384r1, secp521r1, prime256v1]
// - name: transferPolicyId
//   description: Unique identifier of transfer policy.
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the keys.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponses"
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys
// x-sample-call-output: |
//    [
//        {
//            "key_information": {
//                "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//                "algorithm": "AES",
//                "key_length": 256
//            },
//            "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9",
//            "transfer_link": "https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//            "created_at": "2020-09-23T11:16:26.738467277Z"
//        }
//    ]