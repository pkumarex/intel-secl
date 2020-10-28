/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "github.com/intel-secl/intel-secl/v3/pkg/model/kbs"

type KeyTransferPolicies []kbs.KeyTransferPolicyAttributes

// KeyTransferPolicy request/response payload
// swagger:parameters KeyTransferPolicyAttributes
type KeyTransferPolicyAttributes struct {
	// in:body
	Body kbs.KeyTransferPolicyAttributes
}

// KeyTransferPolicyCollection response payload
// swagger:parameters KeyTransferPolicyCollection
type KeyTransferPolicyCollection struct {
	// in:body
	Body KeyTransferPolicies
}

// ---

// swagger:operation POST /key-transfer-policies KeyTransferPolicies CreateKeyTransferPolicy
// ---
//
// description: |
//   Creates a key transfer policy.
//
//   The serialized KeyTransferPolicyAttributes Go struct object represents the content of the request body.
//
//    | Attribute                                    | Description |
//    |----------------------------------------------|-------------|
//    | sgx_enclave_issuer_anyof                     | Array of allowed common names of SGX enclave’s code signing certificate. This is mandatory. The same issuer must be added as a trusted certificate in key server configuration settings. |
//    | sgx_enclave_issuer_product_id_anyof          | Array of (16-bit value) (ISVPRODID). This is mandatory. This is like a qualifier for the issuer so same issuer (code signing) key can sign separate products. |
//    | sgx_enclave_issuer_extended_product_id_anyof | Array of (16-byte value) (ISVPRODID). This is like a qualifier for the issuer so same issuer key can sign separate products, it's like product id but simply bigger (starts in Coffee Lake). |
//    | sgx_enclave_measurement_anyof                | Array of enclave measurements that are allowed to retrieve the key (MRENCLAVE). Expect client to have one of these measurements in the SGX quote (this supports use case of providing key only to an SGX enclave that will enforce the key usage policy locally). |
//    | sgx_config_id_svn                            | Integer. |
//    | sgx_enclave_svn_minimum                      | Minimum version number required. |
//    | sgx_config_id_anyof                          | Array of config id measurements that are allowed to retrieve the key. Required value for the enclave to have when it launched. for loading e.g. Java applets into enclavized JVM, so that enclave measurement is JVM measurement, and when it launches it's configured with this id, so when it loads applet it can measure it and compare to config id in register, and refuse to load applet if wrong (starts in Coffee Lake). |
//    | tls_client_certificate_issuer_cn_anyof       | Array of Common Name to expect on client certificate's issuer field. Expect client certificate to have any one of these issuers. |
//    | tls_client_certificate_san_anyof             | Array of Subject Alternative Name to expect in client certificate's extensions. Expect client certificate to have any of these names. |
//    | tls_client_certificate_san_allof             | Array of Subject Alternative Name to expect in client certificate's extensions. Expect client certificate to have all of these names. |
//    | attestation_type_anyof                       | Array of Attestation Type identifiers that client must support to get the key expect client to advertise these with the key request e.g. "SGX", "KPT2" (note that if key server needs to restrict technologies, then it should list only the ones that can receive the key). |
//    | sgx_enforce_tcb_up_to_date                   | Boolean. |
//
// x-permissions: keys-transfer-policies:create
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
//    "$ref": "#/definitions/KeyTransferPolicyAttributes"
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
//     description: Successfully created the key transfer policy.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicyAttributes"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies
// x-sample-call-input: |
//    {
//        "sgx_enclave_issuer_anyof": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
//        "sgx_enclave_issuer_product_id_anyof": [0],
//        "sgx_enclave_issuer_extended_product_id_anyof": ["00000000000000000000000000000000"],
//        "sgx_enclave_measurement_anyof":["01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"],
//        "sgx_config_id_svn":0,
//        "sgx_enclave_svn_minimum":1,
//        "sgx_config_id_anyof":["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
//        "tls_client_certificate_issuer_cn_anyof":["CMSCA", "CMS TLS Client CA"],
//        "tls_client_certificate_san_allof":["nginx","USA"],
//        "attestation_type_anyof":["SGX"]
//    }
// x-sample-call-output: |
//    {
//        "id": "75d34bf4-80fb-4ca5-8602-a8d82e56b30d",
//        "sgx_enclave_issuer_anyof": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
//        "sgx_enclave_issuer_product_id_anyof": [0],
//        "sgx_enclave_issuer_extended_product_id_anyof": ["00000000000000000000000000000000"],
//        "sgx_enclave_measurement_anyof":["01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"],
//        "sgx_config_id_svn":0,
//        "sgx_enclave_svn_minimum":1,
//        "sgx_config_id_anyof":["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
//        "tls_client_certificate_issuer_cn_anyof":["CMSCA", "CMS TLS Client CA"],
//        "tls_client_certificate_san_allof":["nginx","USA"],
//        "attestation_type_anyof":["SGX"],
//        "created_at": "2020-06-09T01:05:47-0700"
//    }

// ---

// swagger:operation GET /key-transfer-policies/{id} KeyTransferPolicies RetrieveKeyTransferPolicy
// ---
//
// description: |
//   Retrieves a key transfer policy.
//   Returns - The serialized KeyTransferPolicyAttributes Go struct object that was retrieved.
// x-permissions: keys-transfer-policies:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the key transfer policy.
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
//     description: Successfully retrieved the key transfer policy.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicyAttributes"
//   '404':
//     description: KeyTransferPolicy record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies/75d34bf4-80fb-4ca5-8602-a8d82e56b30d
// x-sample-call-output: |
//    {
//        "id": "75d34bf4-80fb-4ca5-8602-a8d82e56b30d",
//        "sgx_enclave_issuer_anyof": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
//        "sgx_enclave_issuer_product_id_anyof": [0],
//        "sgx_enclave_issuer_extended_product_id_anyof": ["00000000000000000000000000000000"],
//        "sgx_enclave_measurement_anyof":["01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"],
//        "sgx_config_id_svn":0,
//        "sgx_enclave_svn_minimum":1,
//        "sgx_config_id_anyof":["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
//        "tls_client_certificate_issuer_cn_anyof":["CMSCA", "CMS TLS Client CA"],
//        "tls_client_certificate_san_allof":["nginx","USA"],
//        "attestation_type_anyof":["SGX"],
//        "created_at": "2020-06-09T01:05:47-0700"
//    }

// ---

// swagger:operation DELETE /key-transfer-policies/{id} KeyTransferPolicies DeleteKeyTransferPolicy
// ---
//
// description: |
//   Deletes a key transfer policy.
// x-permissions: keys-transfer-policies:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the key transfer policy.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the key transfer policy.
//   '404':
//     description: KeyTransferPolicy record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies/75d34bf4-80fb-4ca5-8602-a8d82e56b30d

// ---

// swagger:operation GET /key-transfer-policies KeyTransferPolicies SearchKeyTransferPolicies
// ---
//
// description: |
//   Searches for key transfer policies.
//   Returns - The collection of serialized KeyTransferPolicyAttributes Go struct objects.
// x-permissions: keys-transfer-policies:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the key transfer policies.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicies"
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies
// x-sample-call-output: |
//    [
//        {
//            "id": "75d34bf4-80fb-4ca5-8602-a8d82e56b30d",
//            "sgx_enclave_issuer_anyof": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
//            "sgx_enclave_issuer_product_id_anyof": [0],
//            "sgx_enclave_issuer_extended_product_id_anyof": ["00000000000000000000000000000000"],
//            "sgx_enclave_measurement_anyof":["01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"],
//            "sgx_config_id_svn":0,
//            "sgx_enclave_svn_minimum":1,
//            "sgx_config_id_anyof":["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
//            "tls_client_certificate_issuer_cn_anyof":["CMSCA", "CMS TLS Client CA"],
//            "tls_client_certificate_san_allof":["nginx","USA"],
//            "attestation_type_anyof":["SGX"],
//            "created_at": "2020-06-09T01:05:47-0700"
//        }
//    ]