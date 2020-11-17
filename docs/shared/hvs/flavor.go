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
//                            "source": "127.0.0.1",
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
//                            "source": "127.0.0.1",
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
