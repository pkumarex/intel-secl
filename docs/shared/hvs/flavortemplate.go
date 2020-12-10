/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

// FlavorTemplate response payload
// swagger:parameters FlavorTemplate
type FlavorTemplate struct {
	// in:body
	Body hvs.FlavorTemplate
}

// ---

// swagger:operation GET /flavor-template/{flavortemplate_id} Flavortemplate Retrieve
// ---
// description: |
//   Retrieves a flavor template.
//   Returns - The serialized Flavortemplate Go struct object that was retrieved
// x-permissions: flavor-template:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavortemplate
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
//     description: Successfully retrieved the flavortemplate
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplate"
//   '400':
//     description: Invalid or Bad request
//   '401':
//     description: Unauthorized request
//   '404':
//     description: Flavortemplate record not found
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-template/d6f81340-b033-4fae-8ccf-795430f486e7
// x-sample-call-output: |
// {
//     "id": "d6f81340-b033-4fae-8ccf-795430f486e7",
//     "label": "default_uefi",
//     "condition": [
//         "//meta/vendor='Linux'",
//         "//meta/tpm_version/='2.0'",
//         "//meta/uefi_enabled/='true' or //meta/suefi_enabled/='true'"
//     ],
//     "flavor_parts": {
//         "PLATFORM": {
//             "meta": {
//                 "vendor": "Linux",
//                 "tpm_version": "2.0",
//                 "uefi_enabled": true
//             },
//             "pcr_rules": [
//                 {
//                     "pcr": {
//                         "index": 0,
//                         "bank": "SHA256"
//                     },
//                     "pcr_matches": true
//                 }
//             ]
//         },
//         "OS": {
//             "meta": {
//                 "vendor": "Linux",
//                 "tpm_version": "2.0",
//                 "uefi_enabled": true
//             },
//             "pcr_rules": [
//                 {
//                     "pcr": {
//                         "index": 7,
//                         "bank": "SHA256"
//                     },
//                     "pcr_matches": null,
//                     "eventlog_includes": [
//                         "shim",
//                         "db",
//                         "kek",
//                         "vmlinuz"
//                     ]
//                 }
//             ]
//         }
//     }
// }

// ---
