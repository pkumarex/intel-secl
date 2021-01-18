/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

// FlavorTemplate response payload
// swagger:parameters FlavorTemplate
type FlavorTemplate struct {
	// in: body
	Body hvs.FlavorTemplate
}

// ---

// swagger:operation GET /flavor-templates/{flavortemplate_id} Flavortemplate Retrieve-FlavorTemplate
// ---
//
// description: |
//   Retrieves a flavor template.
//
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
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/d6f81340-b033-4fae-8ccf-795430f486e7
// x-sample-call-output: |
//   {
//       "id": "d6f81340-b033-4fae-8ccf-795430f486e7",
//       "label": "default_uefi",
//       "condition": [
//           "//meta/vendor='Linux'",
//           "//meta/tpm_version/='2.0'",
//           "//meta/uefi_enabled/='true' or //meta/suefi_enabled/='true'"
//       ],
//       "flavor-parts": {
//           "PLATFORM": {
//               "meta": {
//                   "vendor": "Linux",
//                   "tpm_version": "2.0",
//                   "uefi_enabled": true
//               },
//               "pcr_rules": [
//                   {
//                       "pcr": {
//                           "index": 0,
//                           "bank": "SHA256"
//                       },
//                       "pcr_matches": true
//                   }
//               ]
//           },
//           "OS": {
//               "meta": {
//                   "vendor": "Linux",
//                   "tpm_version": "2.0",
//                   "uefi_enabled": true
//               },
//               "pcr_rules": [
//                   {
//                       "pcr": {
//                           "index": 7,
//                           "bank": "SHA256"
//                       },
//                       "pcr_matches": null,
//                       "eventlog_includes": [
//                           "shim",
//                           "db",
//                           "kek",
//                           "vmlinuz"
//                       ]
//                   }
//               ]
//           }
//       }
//   }

// ---

// swagger:operation POST /flavor-templates Flavortemplate Create-FlavorTemplate
// ---
// description: |
//   Flavor Template: Flavor templates are used to implement dynamic flavor generation.
//   The dynamic generation of flavors will be implemented through the use of “flavor-templates”.
//   Flavor template is a JSON which will contain the information about pcr's and rules to be applied for the pcr's for the particular flavor.
//   The purpose of flavor templates is to customize pcr/event-log rules and verifications without code changes.
//   A particular flavor template can be used for the creation of flavors using the condition section in flavor template.
//   The conditions in the flavor template will be matched against the host manifest to determine whether the flavor template can be used for
//   the generation of flavors.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | ID                             | Unique ID of flavor template. |
//    | Label                          | Name of the flavortemplate to be created. |
//    | Condition                      | The “condition” uses meta-data from the host-manifest to determine if the flavor-template should be applied. |
//    | FlavorParts                    | One or more flavor-part entities that are generated by the template. |
//
//   FlavorParts: The type or classification of the flavor. For more information on flavor parts, see the
//   product guide.
//
//       - PLATFORM
//       - OS
//       - ASSET_TAG
//       - HOST_UNIQUE
//       - SOFTWARE
//
//   Creates a Flavor template and stores it in the database.
//
// x-permissions: flavor-template:create
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
//    "$ref": "#/definitions/FlavorTemplate"
// - name: Content-Type
//   description: Content-Type header
//   required: true
//   in: header
//   type: string
// - name: Accept
//   description: Accept header
//   required: true
//   in: header
//   type: string
// responses:
//   '200':
//     description: Successfully created the flavortemplate.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorTemplate"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates
// x-sample-call-input: |
//    {
//      "label": "default-pfr",
//      "condition": [
//         "//meta/vendor='Linux'",
//         "//meta/tpm_version/='2.0'"
//       ],
//      "flavor-parts": {
//           "PLATFORM": {
//                "meta": {
//                    "vendor":"Linux",
//                    "tpm_version": "2.0",
//                    "uefi_enabled": true
//                },
//                "pcr_rules": [
//                    {
//                        "pcr": {
//                            "index": 7,
//                            "bank": "SHA256"
//                        },
//                        "eventlog_includes": ["Inte PFR"]
//                    }
//                ]
//            }
//        }
//    }
//
// x-sample-call-output: |
//    {
//        "id": "3f8a57a8-f6d7-49ea-8309-0e00b997fbce",
//        "label": "default-pfr",
//        "condition": [
//            "//meta/vendor='Linux'",
//            "//meta/tpm_version/='2.0'"
//        ],
//        "flavor-parts": {
//            "PLATFORM": {
//                "meta": {
//                    "vendor": "Linux",
//                    "tpm_version": "2.0",
//                    "uefi_enabled": true
//                },
//                "pcr_rules": [
//                    {
//                        "pcr": {
//                            "index": 7,
//                            "bank": "SHA256"
//                        },
//                        "pcr_matches": null,
//                        "eventlog_includes": [
//                            "Inte PFR"
//                        ]
//                    }
//                ]
//            }
//        }
//    }

// ---

// swagger:operation GET /flavor-templates Flavortemplate Search-FlavorTemplates
// ---
//
// description: |
//   Retrieves all the flavor templates available in the database.
//
// x-permissions: flavor-template:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: include_deleted
//   description: In HVS, template object gets lazy deleted and to include them in search result, set include_deleted flag to true
//   in: query
//   required: false
//   type: string
//   format: bool
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
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates
// x-sample-call-output: |
//   [
//     {
//         "id": "d6f81340-b033-4fae-8ccf-795430f486e7",
//         "label": "default_uefi",
//         "condition": [
//             "//meta/vendor='Linux'",
//             "//meta/tpm_version/='2.0'",
//             "//meta/uefi_enabled/='true' or //meta/suefi_enabled/='true'"
//         ],
//         "flavor-parts": {
//             "PLATFORM": {
//                 "meta": {
//                     "vendor": "Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 0,
//                             "bank": "SHA256"
//                         },
//                         "pcr_matches": true
//                     }
//                 ]
//             },
//             "OS": {
//                 "meta": {
//                     "vendor": "Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "pcr_matches": null,
//                         "eventlog_includes": [
//                             "shim",
//                             "db",
//                             "kek",
//                             "vmlinuz"
//                         ]
//                     }
//                 ]
//             }
//         }
//     },
//     {
//         "id": "3f8a57a8-f6d7-49ea-8309-0e00b997fbce",
//         "label": "default-pfr",
//         "condition": [
//           "//meta/vendor='Linux'",
//           "//meta/tpm_version/='2.0'"
//         ],
//         "flavor-parts": {
//             "PLATFORM": {
//                 "meta": {
//                     "vendor":"Linux",
//                     "tpm_version": "2.0",
//                     "uefi_enabled": true
//                 },
//                 "pcr_rules": [
//                     {
//                         "pcr": {
//                             "index": 7,
//                             "bank": "SHA256"
//                         },
//                         "eventlog_includes": ["Inte PFR"]
//                     }
//                 ]
//             }
//         }
//     }
//   ]

// ---

// swagger:operation DELETE /flavor-templates/{flavortemplate_id} Flavortemplate Delete-FlavorTemplate
// ---
//
// description: |
//   Deletes a flavor template from database.
// x-permissions: flavor-template:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavortemplate_id
//   description: Unique ID of the flavortemplate
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully performed lazy delete on flavor template based on flavortemplate_id
//   '400':
//     description: Invalid or Bad request
//   '401':
//     description: Unauthorized request
//   '404':
//     description: Flavortemplate record not found
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-templates/d6f81340-b033-4fae-8ccf-795430f486e7

// ---
