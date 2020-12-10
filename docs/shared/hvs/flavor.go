/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

//Flavors API request payload
// swagger:parameters FlavorCreateRequest
type FlavorCreateRequest struct {
	// in:body
	Body models.FlavorCreateRequest
}

// Flavors API response payload
// swagger:parameters Flavors
type SignedFlavor struct {
	// in:body
	Body hvs.SignedFlavor
}

// Flavors API response payload
// swagger:parameters SignedFlavorCollection
type SignedFlavorCollection struct {
	// in:body
	Body hvs.SignedFlavorCollection
}

// ---
//
// swagger:operation GET /flavors Flavors Search-Flavors
// ---
//
// description: |
//   A flavor is a set of measurements and metadata organized in a flexible format that allows for ease of further extension. The measurements included in the flavor pertain to various hardware, software and feature categories, and their respective metadata sections provide descriptive information.
//
//   The four current flavor categories:
//   PLATFORM, OS, ASSET_TAG, HOST_UNIQUE, SOFTWARE (See the product guide for a detailed explanation)
//
//   When a flavor is created, it is associated with a flavor group. This means that the measurements for that flavor type are deemed acceptable to obtain a trusted status. If a host, associated with the same flavor group, matches the measurements contained within that flavor, the host is trusted for that particular flavor category (dependent on the flavor group policy). Searches for Flavor records. The identifying parameter can be specified as query to search flavors which will return flavor collection as a result.
//
//   Searches for relevant flavors and returns the signed flavor collection consisting of all the associated flavors.
//   Returns - The serialized Signed FlavorCollection Go struct object that was retrieved.
//
// x-permissions: flavors:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Flavor ID
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: key
//   description: The key can be any “key” field from the meta description section of a flavor. The value can be any “value” of the specified key field in the flavor meta description section. Both key and value query parameters need to be specified.
//   in: query
//   type: string
//   required: false
// - name: value
//   description: The value of the key attribute in flavor description. When provided, key must be provided in query as well.
//   in: query
//   type: string
//   required: false
// - name: flavorgroupId
//   description: The flavor group ID. Returns all the flavors associated with the flavor group ID.
//   in: query
//   type: string
//   required: false
// - name: flavorParts
//   description: An array of flavor parts returns all the flavors associated with the flavor parts
//   in: query
//   type: string
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
//     description: Successfully searched and returned a signed flavor collection.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavorCollection"
//   '400':
//     description: Invalid search criteria provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors?id=f66ac31d-124d-418e-8200-2abf414a9adf
// x-sample-call-output: |
//     {
//        "signed_flavors": [
//        {
//            "flavor": {
//                "meta": {
//                    "schema": {
//                        "uri": "lib:wml:measurements:1.0"
//                    },
//                    "id": "f66ac31d-124d-418e-8200-2abf414a9adf",
//                    "description": {
//                        "flavor_part": "SOFTWARE",
//                        "label": "ISL_Applications",
//                        "digest_algorithm": "SHA384"
//                    }
//                },
//                "software": {
//                    "measurements": {
//                        "opt-trustagent-bin": {
//                            "type": "directoryMeasurementType",
//                            "value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
//                            "Path": "/opt/trustagent/bin",
//                            "Include": ".*"
//                        },
//                        "opt-trustagent-bin-module_analysis_da.sh": {
//                            "type": "fileMeasurementType",
//                            "value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
//                            "Path": "/opt/trustagent/bin/module_analysis_da.sh"
//                        }
//                    },
//                    "cumulative_hash": "be7c2c93d8fd084a6b5ba0b4641f02315bde361202b36c4b88eefefa6928a2c17ac0e65ec6aeb930220cf079e46bcb9f"
//                }
//            },
//            "signature": "aas8/Nv7yYuwx2ZIOMrXFpNf333tBJgr87Dpo7Z5jjUR36Estlb8pYaTGN4Dz9JtbXZy2uIBLr1wjhkHVWm2r1FQq+2yJznXGCpkxWiQSZK84dmmr9tPxIxwxH5U/y8iYgSOnAdvWOn5E7tecil0WcYI/pDlXOs6WtsOWWDsHNXLswzw5qOhqU8WY/2ZVp0l1dnIFT17qQM9SOPi67Jdt75rMAqgl3gOmh9hygqa8KCmF7lrILv3u8ALxNyrqNqbInLGrWaHz5jSka1U+aF6ffmyPFUEmVwT3dp41kCNQshHor9wYo0nD1SAcls8EGZehM/xDokUCjUbfTJfTawYHgwGrXtWEpQVIPI+0xOtLK5NfUl/ZrQiJ9Vn95NQ0FYjfctuDJmlVjCTF/EXiAQmbEAh5WneGvXOzp6Ovp8SoJD5OWRuGhfaT7si3Z0KqGZ2Q6U0ppa8oJ3l4uPSfYlRdg4DFb4PyIScHSo93euQ6AnzGiMT7Tvk3e+lxymkNBwX"
//        }]
//     }

// ---

// swagger:operation POST /flavors Flavors Create-Flavors
// ---
//
// description: |
//   Creates new flavor(s) in database.
//   Flavors can be created by directly providing the flavor content in the request body, or they can be imported from a host. If the flavor content is provided, the flavor parameter must be set in the request. If the flavor is being imported from a host, the host connection string must be specified.
//
//   If a flavor group is not specified, the flavor(s) created will be assigned to the default “automatic” flavor group, with the exception of the host unique flavors, which are associated with the “host_unique” flavor group. If a flavor group is specified and does not already exist, it will be created with a default flavor match policy.
//
//   Partial flavor types can be specified as an array input. In this fashion, the user can choose which flavor types to import from a host. Only flavor types that are defined in the flavor group flavor match policy can be specified. If no partial flavor types are provided, the default action is to attempt retrieval of all flavor types. The response will contain all flavor types that it was able to create.
//
//   If generic flavors are created, all hosts in the flavor group will be added to the backend queue, flavor verification process to re-evaluate their trust status. If host unique flavors are created, the individual affected hosts are added to the flavor verification process.
//
//   The serialized FlavorCreateRequest Go struct object represents the content of the request body.
//
//    | Attribute                      | Description                                     |
//    |--------------------------------|-------------------------------------------------|
//    | connection_string              | (Optional) The host connection string. flavorgroup_names, partial_flavor_types can be provided as optional parameters along with the host connection string. |
//    |                                | For INTEL hosts, this would have the vendor name, the IP addresses, or DNS host name and credentials i.e.: "intel:https://trustagent.server.com:1443 |
//    |                                | For VMware, this includes the vCenter and host IP address or DNS host name i.e.: "vmware:https://vCenterServer.com:443/sdk;h=host;u=vCenterUsername;p=vCenterPassword" |
//    | flavors                        | (Optional) A collection of flavors in the defined flavor format. No other parameters are needed in this case.
//    | signed_flavors                 | (Optional) This is collection of signed flavors consisting of flavor and signature provided by user. |
//    | flavorgroup_names              | (Optional) Flavor group names that the created flavor(s) will be associated with. If not provided, created flavor will be associated with automatic flavor group. |
//    | partial_flavor_types           | (Optional) List array input of flavor types to be imported from a host. Partial flavor type can be any of the following: PLATFORM, OS, ASSET_TAG, HOST_UNIQUE, SOFTWARE. Can be provided with the host connection string. See the product guide for more details on how flavor types are broken down for each host type. |
//
// x-permissions: flavors:create
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
//    "$ref": "#/definitions/FlavorCreateRequest"
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
//     description: Successfully created the flavors.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavorCollection"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors
// x-sample-call-input: |
//      {
//          "connection_string" : "https://tagent-ip:1443/",
//          "partial_flavor_types" : ["OS", "HOST_UNIQUE"]
//      }
// x-sample-call-output: |
//    {
//        "signed_flavors": [
//            {
//                "flavor": {
//                    "meta": {
//                        "id": "ee7c7d49-1e80-4198-8c9f-04319b8a3db9",
//                        "description": {
//                            "flavor_part": "OS",
//                            "source": "computepurley144.fm.intel.com",
//                            "label": "INTEL_RedHatEnterprise_8.1_Virsh_4.5.0_05-27-2020_02-57-56",
//                            "os_name": "RedHatEnterprise",
//                            "os_version": "8.1",
//                            "vmm_name": "Virsh",
//                            "vmm_version": "4.5.0",
//                            "tpm_version": "2.0",
//                            "tboot_installed": "true"
//                        },
//                        "vendor": "INTEL"
//                    },
//                    "bios": {
//                        "bios_name": "Intel Corporation",
//                        "bios_version": "SE5C620.86B.00.01.6016.032720190737"
//                    },
//                    "pcrs": {
//                        "SHA1": {
//                            "pcr_17": {
//                                "value": "c83860a466f7595bac3558394a2c4df0e0ac0cb1",
//                                "event": [
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
//                                        "value": "5b870664c50ead0421e4a67514724759aa9a9d5b",
//                                        "label": "vmlinuz",
//                                        "info": {
//                                            "ComponentName": "vmlinuz",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    }
//                                ]
//                            }
//                        },
//                        "SHA256": {
//                            "pcr_17": {
//                                "value": "b9a3b48397df5cbd8f184c3a85324c3f85723482b7f71a2f72fb0a5d239d170c",
//                                "event": [
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
//                                        "value": "348a6284f46123a913681d53a201c05750d4527483ceaa2a2adbc7dda52cf506",
//                                        "label": "vmlinuz",
//                                        "info": {
//                                            "ComponentName": "vmlinuz",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    }
//                                ]
//                            }
//                        }
//                    }
//                },
//                "signature": "aas8/Nv7yYuwx2ZIOMrXFpNf333tBJgr87Dpo7Z5jjUR36Estlb8pYaTGN4Dz9JtbXZy2uIBLr1wjhkHVWm2r1FQq+2yJznXGCpkxWiQSZK84dmmr9tPxIxwxH5U/y8iYgSOnAdvWOn5E7tecil0WcYI/pDlXOs6WtsOWWDsHNXLswzw5qOhqU8WY/2ZVp0l1dnIFT17qQM9SOPi67Jdt75rMAqgl3gOmh9hygqa8KCmF7lrILv3u8ALxNyrqNqbInLGrWaHz5jSka1U+aF6ffmyPFUEmVwT3dp41kCNQshHor9wYo0nD1SAcls8EGZehM/xDokUCjUbfTJfTawYHgwGrXtWEpQVIPI+0xOtLK5NfUl/ZrQiJ9Vn95NQ0FYjfctuDJmlVjCTF/EXiAQmbEAh5WneGvXOzp6Ovp8SoJD5OWRuGhfaT7si3Z0KqGZ2Q6U0ppa8oJ3l4uPSfYlRdg4DFb4PyIScHSo93euQ6AnzGiMT7Tvk3e+lxymkNBwX"
//            },
//            {
//                "flavor": {
//                    "meta": {
//                        "id": "b98df5dd-ec68-4115-944f-99e9a022b0ed",
//                        "description": {
//                            "flavor_part": "HOST_UNIQUE",
//                            "source": "computepurley144.fm.intel.com",
//                            "label": "INTEL_00B61DA0-5ADA-E811-906E-00163566263E_05-27-2020_02-57-56",
//                            "bios_name": "Intel Corporation",
//                            "bios_version": "SE5C620.86B.00.01.6016.032720190737",
//                            "os_name": "RedHatEnterprise",
//                            "os_version": "8.1",
//                            "tpm_version": "2.0",
//                            "hardware_uuid": "00B61DA0-5ADA-E811-906E-00163566263E",
//                            "tboot_installed": "true"
//                        },
//                        "vendor": "INTEL"
//                    },
//                    "bios": {
//                        "bios_name": "Intel Corporation",
//                        "bios_version": "SE5C620.86B.00.01.6016.032720190737"
//                    },
//                    "pcrs": {
//                        "SHA1": {
//                            "pcr_17": {
//                                "value": "c83860a466f7595bac3558394a2c4df0e0ac0cb1",
//                                "event": [
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
//                                        "value": "9069ca78e7450a285173431b3e52c5c25299e473",
//                                        "label": "LCP_CONTROL_HASH",
//                                        "info": {
//                                            "ComponentName": "LCP_CONTROL_HASH",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    },
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
//                                        "value": "f51a0544599649e9e356f67beae16dd78994a23e",
//                                        "label": "initrd",
//                                        "info": {
//                                            "ComponentName": "initrd",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    }
//                                ]
//                            },
//                            "pcr_18": {
//                                "value": "86da61107994a14c0d154fd87ca509f82377aa30",
//                                "event": [
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha1",
//                                        "value": "9069ca78e7450a285173431b3e52c5c25299e473",
//                                        "label": "LCP_CONTROL_HASH",
//                                        "info": {
//                                            "ComponentName": "LCP_CONTROL_HASH",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    }
//                                ]
//                            }
//                        },
//                        "SHA256": {
//                            "pcr_17": {
//                                "value": "b9a3b48397df5cbd8f184c3a85324c3f85723482b7f71a2f72fb0a5d239d170c",
//                                "event": [
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
//                                        "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                        "label": "LCP_CONTROL_HASH",
//                                        "info": {
//                                            "ComponentName": "LCP_CONTROL_HASH",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                     },
//                                     {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
//                                        "value": "22cd1ae4ecf934348d4a970e1400956327971382ad9697a59d3e5de5f2d0160f",
//                                        "label": "initrd",
//                                        "info": {
//                                            "ComponentName": "initrd",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    }
//                                ]
//                            },
//                            "pcr_18": {
//                                "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
//                                "event": [
//                                    {
//                                        "digest_type": "com.intel.mtwilson.core.common.model.MeasurementSha256",
//                                        "value": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
//                                        "label": "LCP_CONTROL_HASH",
//                                        "info": {
//                                            "ComponentName": "LCP_CONTROL_HASH",
//                                            "EventName": "OpenSource.EventName"
//                                        }
//                                    }
//                                ]
//                            }
//                        }
//                    }
//                },
//                "signature": "mT2qGOj6p0+sRtM5RuXxAZ4Hg0bDmkqILPVPMyTURYQNcSNKqP9vG9wek/7KMdoIpP20Qc9z8tdNIHbQqdBS21j2Z3tI2WMdGWyFkEgqlZzubtVFnQ3WspMAq1D+hhJWsAUDX+OF2kcFmZSoS7lI8aVjGkBs94k47s7FqeCyGzKnDzFTWSFX/mIWBNMcFMQ3tDzYJZrp70tiu4r1AdrznqfAHWpgeXce4H7a0pk5VmHAQ4jevsTs0LkM8osKLhiI44NOBRie1gQTLnGC1yQ/mTiA4PXeyg6Xig+sUqja/fim2fBYkHaZm3GnVmsvlEddWcQEtPvsnGDI7nV+bxn24f75YwpbB80jmf8giZMWamXw68VZwdrwhMofyslVmh3SGKY4/0dYGE1H1DFZB75w753RXi6rH8p4xcnt3FOL9vEDNX0BTC+2ro5lORCEP3q2JHdlbldKw3a4GWBGt3qcTBQSRUVR++/xjOWNk0C3oEb28XL8Y6QgBQBz+EFrT7"
//            }
//        ]
//    }

// ---

// swagger:operation GET /flavors/{flavor_id} Flavors Retrieve-Flavor
// ---
//
// description: |
//   Retrieves a flavor.
//   Returns - The serialized Signed Flavor Go struct object that was retrieved.
// x-permissions: flavors:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: flavor_id
//   description: Unique UUID of the Flavor.
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
//     description: Successfully retrieved the flavor.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/SignedFlavor"
//   '404':
//     description: No flavor with the provided flavor ID found.
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors/f66ac31d-124d-418e-8200-2abf414a9adf
// x-sample-call-output: |
//  {
//    "flavor": {
//        "meta": {
//            "schema": {
//                "uri": "lib:wml:measurements:1.0"
//            },
//            "id": "f66ac31d-124d-418e-8200-2abf414a9adf",
//            "description": {
//                "flavor_part": "SOFTWARE",
//                "label": "ISL_Applications123",
//                "digest_algorithm": "SHA384"
//            }
//        },
//        "software": {
//            "measurements": {
//                "opt-trustagent-bin": {
//                    "type": "directoryMeasurementType",
//                    "value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
//                    "Path": "/opt/trustagent/bin",
//                    "Include": ".*"
//                },
//                "opt-trustagent-bin-module_analysis_da.sh": {
//                    "type": "fileMeasurementType",
//                    "value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
//                    "Path": "/opt/trustagent/bin/module_analysis_da.sh"
//                }
//            },
//            "cumulative_hash": "be7c2c93d8fd084a6b5ba0b4641f02315bde361202b36c4b88eefefa6928a2c17ac0e65ec6aeb930220cf079e46bcb9f"
//        }
//    },
//    "signature": "aas8/Nv7yYuwx2ZIOMrXFpNf333tBJgr87Dpo7Z5jjUR36Estlb8pYaTGN4Dz9JtbXZy2uIBLr1wjhkHVWm2r1FQq+2yJznXGCpkxWiQSZK84dmmr9tPxIxwxH5U/y8iYgSOnAdvWOn5E7tecil0WcYI/pDlXOs6WtsOWWDsHNXLswzw5qOhqU8WY/2ZVp0l1dnIFT17qQM9SOPi67Jdt75rMAqgl3gOmh9hygqa8KCmF7lrILv3u8ALxNyrqNqbInLGrWaHz5jSka1U+aF6ffmyPFUEmVwT3dp41kCNQshHor9wYo0nD1SAcls8EGZehM/xDokUCjUbfTJfTawYHgwGrXtWEpQVIPI+0xOtLK5NfUl/ZrQiJ9Vn95NQ0FYjfctuDJmlVjCTF/EXiAQmbEAh5WneGvXOzp6Ovp8SoJD5OWRuGhfaT7si3Z0KqGZ2Q6U0ppa8oJ3l4uPSfYlRdg4DFb4PyIScHSo93euQ6AnzGiMT7Tvk3e+lxymkNBwX"
//  }

// ---

// swagger:operation DELETE /flavors/{flavor_id} Flavors Delete-Flavor
// ---
//
// description: |
//   Deletes a flavor.
// x-permissions: flavors:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: flavor_id
//   description: Unique UUID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the flavor.
//   '404':
//     description: No flavor with the provided flavor ID found.
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavors/f66ac31d-124d-418e-8200-2abf414a9adf

// ---

// swagger:operation POST /upgrade-flavor/ Flavors Upgrade-Flavors
// ---
// description: |
//   Converts Flavor parts from older versions(3.x) to latest Flavor part.
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
//    "$ref": "#/definitions/SignedFlavorCollection"
// - name: Content-Type
//   required: true
//   in: header
//   type: string
// - name: Accept
//   required: true
//   in: header
//   type: string
// responses:
//   '200':
//     description: Successfully created the latest flavorpart from previous flavor part.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/FlavorSchema"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-part/
// x-sample-call-input: |
//  [
//    {
//       "flavor":{
//          "meta":{
//             "id":"4807508d-9d93-4f3b-8da2-0d6dfebb4352",
//             "description":{
//                "flavor_part":"PLATFORM",
//                "source":"localhost.localdomain",
//                "label":"INTEL_IntelCorporation_SE5C620.86B.00.01.0014.070920180847_TPM_TXT_2020-08-21T00:11:46.613123-07:00",
//                "bios_name":"Intel Corporation",
//                "bios_version":"SE5C620.86B.00.01.0014.070920180847",
//                "tpm_version":"2.0",
//                "tboot_installed":"true"
//             },
//             "vendor":"INTEL"
//          },
//          "bios":{
//             "bios_name":"Intel Corporation",
//             "bios_version":"SE5C620.86B.00.01.0014.070920180847"
//          },
//          "hardware":{
//             "processor_info":"54 06 05 00 FF FB EB BF",
//             "processor_flags":"FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
//             "feature":{
//                "TXT":{
//                   "enabled":true
//                },
//                "TPM":{
//                   "enabled":true,
//                   "version":"2.0",
//                   "pcr_banks":[
//                      "SHA1",
//                      "SHA256"
//                   ]
//                }
//             }
//          },
//          "pcrs":{
//             "SHA1":{
//                "pcr_0":{
//                   "value":"3f95ecbb0bb8e66e54d3f9e4dbae8fe57fed96f0"
//                },
//                "pcr_17":{
//                   "value":"efe2d6446e4adf17a32c84e89df1f097997c1ed2",
//                   "event":[
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"19f7c22f6c92d9555d792466b2097443444ebd26",
//                         "label":"HASH_START",
//                         "info":{
//                            "ComponentName":"HASH_START",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"3cf4a5c90911c21f6ea71f4ca84425f8e65a2be7",
//                         "label":"BIOSAC_REG_DATA",
//                         "info":{
//                            "ComponentName":"BIOSAC_REG_DATA",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"3c585604e87f855973731fea83e21fab9392d2fc",
//                         "label":"CPU_SCRTM_STAT",
//                         "info":{
//                            "ComponentName":"CPU_SCRTM_STAT",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                         "label":"LCP_DETAILS_HASH",
//                         "info":{
//                            "ComponentName":"LCP_DETAILS_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                         "label":"STM_HASH",
//                         "info":{
//                            "ComponentName":"STM_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
//                         "label":"OSSINITDATA_CAP_HASH",
//                         "info":{
//                            "ComponentName":"OSSINITDATA_CAP_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"55b29518b96e8afa75f32055ed414575f61e50a0",
//                         "label":"MLE_HASH",
//                         "info":{
//                            "ComponentName":"MLE_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
//                         "label":"NV_INFO_HASH",
//                         "info":{
//                            "ComponentName":"NV_INFO_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"ca96de412b4e8c062e570d3013d2fccb4b20250a",
//                         "label":"tb_policy",
//                         "info":{
//                            "ComponentName":"tb_policy",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      }
//                   ]
//                },
//                "pcr_18":{
//                   "value":"86da61107994a14c0d154fd87ca509f82377aa30",
//                   "event":[
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"a395b723712b3711a89c2bb5295386c0db85fe44",
//                         "label":"SINIT_PUBKEY_HASH",
//                         "info":{
//                            "ComponentName":"SINIT_PUBKEY_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"3c585604e87f855973731fea83e21fab9392d2fc",
//                         "label":"CPU_SCRTM_STAT",
//                         "info":{
//                            "ComponentName":"CPU_SCRTM_STAT",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
//                         "label":"OSSINITDATA_CAP_HASH",
//                         "info":{
//                            "ComponentName":"OSSINITDATA_CAP_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"5ba93c9db0cff93f52b521d7420e43f6eda2784f",
//                         "label":"LCP_AUTHORITIES_HASH",
//                         "info":{
//                            "ComponentName":"LCP_AUTHORITIES_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
//                         "label":"NV_INFO_HASH",
//                         "info":{
//                            "ComponentName":"NV_INFO_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"ca96de412b4e8c062e570d3013d2fccb4b20250a",
//                         "label":"tb_policy",
//                         "info":{
//                            "ComponentName":"tb_policy",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      }
//                   ]
//                }
//             },
//             "SHA256":{
//                "pcr_0":{
//                   "value":"1009d6bc1d92739e4e8e3c6819364f9149ee652804565b83bf731bdb6352b2a6"
//                },
//                "pcr_17":{
//                   "value":"dbb54f92a3cd889016bf4fe9d08ce450eed6a7e9ab60d7b8f618b44781baf83b",
//                   "event":[
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"14fc51186adf98be977b9e9b65fc9ee26df0599c4f45804fcc45d0bdcf5025db",
//                         "label":"HASH_START",
//                         "info":{
//                            "ComponentName":"HASH_START",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"c61aaa86c13133a0f1e661faf82e74ba199cd79cef652097e638a756bd194428",
//                         "label":"BIOSAC_REG_DATA",
//                         "info":{
//                            "ComponentName":"BIOSAC_REG_DATA",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
//                         "label":"CPU_SCRTM_STAT",
//                         "info":{
//                            "ComponentName":"CPU_SCRTM_STAT",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                         "label":"LCP_DETAILS_HASH",
//                         "info":{
//                            "ComponentName":"LCP_DETAILS_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                         "label":"STM_HASH",
//                         "info":{
//                            "ComponentName":"STM_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
//                         "label":"OSSINITDATA_CAP_HASH",
//                         "info":{
//                            "ComponentName":"OSSINITDATA_CAP_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"89b2829048f5ee138a25e528cbd1da64f32fa1b484a369581288868ee2e7a549",
//                         "label":"MLE_HASH",
//                         "info":{
//                            "ComponentName":"MLE_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
//                         "label":"NV_INFO_HASH",
//                         "info":{
//                            "ComponentName":"NV_INFO_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
//                         "label":"tb_policy",
//                         "info":{
//                            "ComponentName":"tb_policy",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      }
//                   ]
//                },
//                "pcr_18":{
//                   "value":"d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
//                   "event":[
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
//                         "label":"SINIT_PUBKEY_HASH",
//                         "info":{
//                            "ComponentName":"SINIT_PUBKEY_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
//                         "label":"CPU_SCRTM_STAT",
//                         "info":{
//                            "ComponentName":"CPU_SCRTM_STAT",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
//                         "label":"OSSINITDATA_CAP_HASH",
//                         "info":{
//                            "ComponentName":"OSSINITDATA_CAP_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
//                         "label":"LCP_AUTHORITIES_HASH",
//                         "info":{
//                            "ComponentName":"LCP_AUTHORITIES_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
//                         "label":"NV_INFO_HASH",
//                         "info":{
//                            "ComponentName":"NV_INFO_HASH",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      },
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
//                         "label":"tb_policy",
//                         "info":{
//                            "ComponentName":"tb_policy",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      }
//                   ]
//                }
//             }
//          }
//       },
//       "signature":"QTpd7Hupxu196puAAQ953TgWQpWDW3IT40abiCfHN4CpV53Ke9tYfrzRzpX3vCsWBfmkd3AdVRlhUDlH02tOxOTUiAJN35abYe/PHM1rQG3j7uuK9IH65VE3rCFUxXwnfclwNH1+5sxmMcvKZVYvZQTHJdzr9M1Efo0RXioK+GoUJZzN956QSc22Z97Na5aVD5pPO7A5gCYj1BNkQS2sRmiVKdPOfcsYFUHwD5G4+CIjwzZqH1etAeYFNsW8tKnJKa3CWQ17NpgmFy0INClG3Tyubt7PpdZyGsu0anAUfH4x9h2pDlpm37cs4WNKJmgshsaA/RujxY6Kc4+YGdEEAN9l5RSnnfNSdgDKmrwkL2jNnxPky+PpSXNLr5927NlSXRJ1iJU/9mx6cG6ssZXVItGsEHbWj/uCn8xJ9Pls4Zm3C/UGUk6QmYNl8R3GultS4qaLs2eYHeU9xPIhuSXXAHlzZEsKSY/z94jWyDpkHk8hq3ODSlN3EW5NZqt9zWNP"
//    },
//    {
//       "flavor":{
//          "meta":{
//             "id":"98c911c5-72a2-42a8-84b4-eb45bc422d4f",
//             "description":{
//                "flavor_part":"OS",
//                "source":"localhost.localdomain",
//                "label":"INTEL_RedHatEnterprise_8.2_Docker_19.03.12_2020-08-21T00:11:46.631501-07:00",
//                "os_name":"RedHatEnterprise",
//                "os_version":"8.2",
//                "vmm_name":"Docker",
//                "vmm_version":"19.03.12",
//                "tpm_version":"2.0",
//                "tboot_installed":"true"
//             },
//             "vendor":"INTEL"
//          },
//          "bios":{
//             "bios_name":"Intel Corporation",
//             "bios_version":"SE5C620.86B.00.01.0014.070920180847"
//          },
//          "pcrs":{
//             "SHA1":{
//                "pcr_17":{
//                   "value":"efe2d6446e4adf17a32c84e89df1f097997c1ed2",
//                   "event":[
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha1",
//                         "value":"fbe8c6890de8cce6422637beac0a28b32f6939b1",
//                         "label":"vmlinuz",
//                         "info":{
//                            "ComponentName":"vmlinuz",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      }
//                   ]
//                }
//             },
//             "SHA256":{
//                "pcr_17":{
//                   "value":"dbb54f92a3cd889016bf4fe9d08ce450eed6a7e9ab60d7b8f618b44781baf83b",
//                   "event":[
//                      {
//                         "digest_type":"com.intel.mtwilson.core.common.model.MeasurementSha256",
//                         "value":"d4b319df2b01841ab98398dca33d8fcefcada45c40456711fa9b8551cf832649",
//                         "label":"vmlinuz",
//                         "info":{
//                            "ComponentName":"vmlinuz",
//                            "EventName":"OpenSource.EventName"
//                         }
//                      }
//                   ]
//                }
//             }
//          }
//       },
//       "signature":"RrO9buU5JTe78dZqE4LKowYWRg7lSL8Gzx9RwqSbhfL/e5qvKSsr669kz8aRMLZbxTJDmHlJedmASuejhxpCZEd2cSt1/z8rL8axuqLlhexv5tZ5JI4pO/lXxV3K5uWGi9x7kRLvGGw3RME53eJZsFiZWOGIxGfKTPcYsoR2+3ReMeoJkhdtjnvkdLSQM/o61pPDb+jW/JZiI2WuB383b1L+hC+I20t1NNt2Vs6092h8Qzfpsj/BD6AG3FE75SwjfQVMZKB6zbWb1OQpIDBT7niHHyDhvGv44MZ6f81bbwlHcGO1SwzKVJuiOq24oI5cXj+S2xJ5Mu2Kuhx1gXKUVX84qk0DWbYPY0mMra7ECLU/06HrA8hYubcvFN2CG4TCltliSgFoBL1OLsosc25Y3thNQgZCVPQavLxfy+E82zjpb79wU8HY7MrJ61YvbIh+g3rfdL+a4o713XkZJ+lBRuO2ETxqry1pohJV4fAPwTcdTZ8/hucrVwoySDZG1iWT"
//    }
//  ]
// x-sample-call-output: |
//   [
//     {
//         "id": "890bc756-40da-4bde-a707-3b27b23e0149",
//         "flavor_part": "PLATFORM",
//         "meta": {
//             "template_id": "3392f153-705b-47b2-aa81-d699c57d9568",
//             "template_label": "linux-tpm2-tboot",
//             "source": "computer1.intel.com",
//             "bios_name": "Intel Corporation",
//             "bios_version": "SE5C620.86B.0X.01.0155.073020181001",
//             "tboot_installed": "true"
//         },
//         "pcrs": [
//             {
//                 "pcr": {
//                     "index": 0,
//                     "bank": "SHA256"
//                 },
//                 "measurement": "987c560472a458a563a21e33b2e927383c7d379340d5a98c8529ab82ecda79f9",
//                 "pcr_matches": true
//             },
//             {
//                 "pcr": {
//                     "index": 17,
//                     "bank": "SHA256"
//                 },
//                 "measurement": "9b34aeaec0aa4073c63c37d607e4d039203444318adf204b9ecbf1e6a853467d",
//                 "eventlog_equals": {
//                     "tpm_events": [
//                         {
//                             "type_id": 900,
//                             "measurement": "940a487b3a2b3a82858b18c20f55ad9c73522f43aab071f62350093bd7c2d6ba",
//                             "tags": ["HASH_START"]
//                         },
//                         {
//                             "type_id": 901,
//                             "measurement": "7980d1a2034e18a33da6fde28ddd8a296c7147a3e4cea6dc32997f4fc40a97a5",
//                             "tags": ["BIOSAC_REG_DATA"]
//                         }
//                     ],
//                     "exclude_tags": ["commandLine."]
//                 }
//             }
//         ]
//     },
//     {
//         "id": "61a8c756-40da-4bde-a707-3b27b23e0149",
//         "flavor_part": "OS",
//         "meta": {
//             "template_id": "3392f153-705b-47b2-aa81-d699c57d9568",
//             "template_label": "linux-tpm2-tboot",
//             "source": "computer1.intel.com",
//             "os_name": "RedHatEnterprise",
//             "os_version": "8.1",
//             "vmm_name": "Docker",
//             "vmm_version": "19.03.5",
//             "tpm_version": "2.0",
//             "tboot_installed": "true"
//         },
//         "pcrs": [
//             {
//                 "pcr": {
//                     "index": 17,
//                     "bank": "SHA256"
//                 },
//                 "measurement": "9b34aeaec0aa4073c63c37d607e4d039203444318adf204b9ecbf1e6a853467d",
//                 "eventlog_includes": [
//                     {
//                         "type_id": 409,
//                         "measurement": "eaa699b0d1f10fd7eccdcab9813b174f68b4327b022bf05e93a38b17c1c8e8dc",
//                         "tags": ["vmlinuz"]
//                     }
//                 ]
//             }
//         ]
//     }
//    ]

// ---
