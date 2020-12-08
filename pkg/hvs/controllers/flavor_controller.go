/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	"github.com/antchfx/jsonquery"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	dm "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor"
	fc "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	fConst "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	fm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	fType "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	fu "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	hcType "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type FlavorController struct {
	FStore    domain.FlavorStore
	FGStore   domain.FlavorGroupStore
	HStore    domain.HostStore
	TCStore   domain.TagCertificateStore
	HTManager domain.HostTrustManager
	CertStore *dm.CertificatesStore
	HostCon   HostController
	FTStore   domain.FlavorTemplateStore
}

var flavorSearchParams = map[string]bool{"id": true, "key": true, "value": true, "flavorgroupId": true, "flavorParts": true}

var steffyHostManifest = `{
    "aik_certificate": "MIIDUDCCAbigAwIBAgIQc9p7kDRovnuwDgprM680cDANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDExdIVlMgUHJpdmFjeSBDZXJ0aWZpY2F0ZTAeFw0yMDExMDYxMzQzNTBaFw0yNTExMDYxMzQzNTBaMCIxIDAeBgNVBAMTF0hWUyBQcml2YWN5IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsKNqqEIAQg51Rm7y0oxD6yG+pv3+oONIhzPdLJN4XeUSr6bwMUYYZnBEKPwVvaCSSnxINuX3SxbVg+sjQI0bu2tGiuI5ErRgYielSoKFpzFgIENHemlu79T7LZU42hpJZBoY868Xtz0JJGfjxc2FDGqX4fXvkWQQG0SWAL3I06+9hYBnk+owqoxH22Pz6RoiUep1CYbnDtCJBg+1giaIxbuficQCoVX0AzkYChFSBMBqP+xfseKfj7Zm6tpoO8ILMIWu30oJ4MQaWLNL0B7xWSPIYueeu/ie120ger26+tb/MmzNbHBXXjMxLljvgGjcN47IHRVCQ5fPNnWqR9y9uQIDAQABowIwADANBgkqhkiG9w0BAQsFAAOCAYEA0NmaHYse8kU0BFWij7rx5QgyYolZooY2rXyXm5IDX9DF7Tz3UnX/1nE0s5dhqxLoFTOdBuL5C6EgWrRqGPP736vdTOL9R0GjXCqrrk5/fmxK0a6UZfffaeikM2+Isw5wlMUJHev55KL4s1ahDNk96XdQoTdRL5WSx8SVBcR4F+u4dxYJUU/hdGTmFeU8rxUy/jpfvnpnxdncESX+JHd6kRufHWQ+8jFJVXm+jb9Iy+nmMfLz3gQrrNoBZfj9wSiQ1lJqq6Av5rXpz0egUhhK2PBe/h/Cnh0L02iezhGWM8WSXmdE5E1B806u0PpODVcDGLZHD73dMJWDt+Q5qxJDxlDXT2BQTqUWikEbgFGYwVEKttAxQojUMobmud/vo+RbxdroDmIw7xN5KmamV1RbEiE3Ui61gAMRl9p68mwEouBd1iI1NshyYjFaj3btwzh1eaRB8fBEH5rTuHtgmysxP8Zcy6wyB5DLu8oNUF73BxuLe0H3XAx7CSRfZ0vVv73f",
    "asset_tag_digest": "9nmVcW3oWtyWa1+KKA/0VfbuuvU/VjKFz+9lQoI+hB0ZoVpKktwl9AhHAcjBPrcM",
    "host_info": {
        "os_name": "RedHatEnterprise",
        "os_version": "8.1",
        "bios_version": "SE5C620.86B.00.01.5016.032520190947",
        "vmm_name": "Docker",
        "vmm_version": "19.03.5",
        "processor_info": "54 06 05 00 FF FB EB BF",
        "host_name": "localhost.localdomain",
        "bios_name": "Intel Corporation",
        "hardware_uuid": "80acb25c-95bd-e811-906e-00163566263e",
        "process_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
        "no_of_sockets": "2",
		"tboot_installed": "true",
		"vendor": "Linux",
		"tpm_version": "2.0",
		"uefi_enabled": "true",
		"suefi_enabled": "true",
        "hardware_features": {
            "TXT": {
                "enabled": "true"
            },
            "TPM": {
                "enabled": "true",
                "meta": {
                    "tpm_version": "2.0",
                    "pcr_banks": "SHA1_SHA256"
                }
            }
        },
        "installed_components": [
            "tagent",
            "wlagent"
        ]
    },
    "pcr_manifest": {
        "sha1pcrs": [
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_0",
                "value": "17995d6d77357fa151ce2456dcdf06abd1c927c7",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_1",
                "value": "27be382630dad36850b9f93dbf9286911beaebf1",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_2",
                "value": "0adac824d61d6469bae7b4da8ac7a7d4914f42f2",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_3",
                "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_4",
                "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_5",
                "value": "ce4c5e966536394ebc6c55dcd9cc73f4f4a7ce3b",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_6",
                "value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_7",
                "value": "518bd167271fbb64589c61e43d8c0165861431d8",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_8",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_9",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_10",
                "value": "31c824c0b403f9a4df213f8333fa2e41c511537f",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_11",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_12",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_13",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_14",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_15",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_16",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_17",
                "value": "fd348998cbbed63b1394aa2f685f2143e5e859ac",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_18",
                "value": "86da61107994a14c0d154fd87ca509f82377aa30",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_19",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_20",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_21",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_22",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
                "index": "pcr_23",
                "value": "0000000000000000000000000000000000000000",
                "pcr_bank": "SHA1"
            }
        ],
        "sha2pcrs": [
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_0",
                "value": "e567dabf0849c2f0775dcb6b3ee3b9f36e763722a4855adf925fae7c98e686d0",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_1",
                "value": "9d7d64cd2b545946bfca0b7f9c83993805a307e1635f167dc7e4c9970876da5d",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_2",
                "value": "0a8307b94e609d351f2928e05146a1805285456bc4846c0752029809e08c7f4a",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_3",
                "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_4",
                "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_5",
                "value": "f7a40d6564cb00d3846f32ed392f6727ec3ef050739576365006daccceaaa5f2",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_6",
                "value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_7",
                "value": "65caf8dd1e0ea7a6347b635d2b379c93b9a1351edc2afc3ecda700e534eb3068",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_8",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_9",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_10",
                "value": "d20120d3a1f02b4081298bfc54875473c469fb695bcddb6e8d046e26b98b4950",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_11",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_12",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_13",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_14",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_15",
                "value": "fd985f13771bac507a6c064df4c42862be197df7013845532152993f52f18f24",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_16",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_17",
                "value": "3715721306d7e61efd5c18a349ee7e8beb8387c1a45dd053d8175960f51d3394",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_18",
                "value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_19",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_20",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_21",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_22",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            },
            {
                "digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
                "index": "pcr_23",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                "pcr_bank": "SHA256"
            }
        ],
        "pcr_event_log_map": {
            "SHA1": [
                {
                    "pcr": {
                        "index": 17,
                        "bank": "SHA1"
                    },
                    "tpm_events": [
                        {
                            "measurement": "7636dbbb8b8f40a9b7b7140e6da43e5bf2f531de",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "HASH_START"
                        },
                        {
                            "measurement": "9dcd8ac722c21e60652f0961ad6fe31938c4cc8f",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
							"type_name": "BIOSAC_REG_DATA"
                        },
                        {
                            "measurement": "3c585604e87f855973731fea83e21fab9392d2fc",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "CPU_SCRTM_STAT"
                        },
                        {
                            "measurement": "9069ca78e7450a285173431b3e52c5c25299e473",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "LCP_CONTROL_HASH"
                        },
                        {
                            "measurement": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "LCP_DETAILS_HASH"
                        },
                        {
                            "measurement": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "STM_HASH"
                        },
                        {
                            "measurement": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "OSSINITDATA_CAP_HASH"
                        },
                        {
                            "measurement": "95ef7fa2906f31b764c87e7d0db40f64af81685d",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "MLE_HASH"
                        },
                        {
                            "measurement": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "NV_INFO_HASH"
                        },
                        {
                            "measurement": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "tb_policy"
                        },
                        {
                            "measurement": "fbe8c6890de8cce6422637beac0a28b32f6939b1",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "vmlinuz"
                        },
                        {
                            "measurement": "ce5ea127ff561cfbf15ef7ee8affc7a402ca7c31",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
							"tags" :[],
                            "type_name": "initrd"
                        }
                    ]
                },
                {
                    "pcr": {
                        "index": 18,
                        "bank": "SHA1"
                    },
                    "tpm_events": [
                        {
                            "measurement": "a395b723712b3711a89c2bb5295386c0db85fe44",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "SINIT_PUBKEY_HASH"
                        },
                        {
                            "measurement": "3c585604e87f855973731fea83e21fab9392d2fc",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "CPU_SCRTM_STAT"
                        },
                        {
                            "measurement": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "OSSINITDATA_CAP_HASH"
                        },
                        {
                            "measurement": "9069ca78e7450a285173431b3e52c5c25299e473",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "LCP_CONTROL_HASH"
                        },
                        {
                            "measurement": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "LCP_AUTHORITIES_HASH"
                        },
                        {
                            "measurement": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "NV_INFO_HASH"
                        },
                        {
                            "measurement": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha1",
                            "type_name": "tb_policy"
                        }
                    ]
                }
            ],
            "SHA256": [
                {
                    "pcr": {
                        "index": 15,
                        "bank": "SHA256"
                    },
                    "tpm_events": [
                        {
                            "measurement": "6bfa92fefcc7ddd4ca1871f246e716c137f82d309423e03ace6068b0f76f4083",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "ISecL_Default_Workload_Flavor_v2.1-3cdaa538-7816-419a-81c8-9e86d1a3b51f"
                        },
                        {
                            "measurement": "f4b9dde27d77788d82466005c3c2b467e0bcaed6a4852cec31291835a99ee54a",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "ISecL_Default_Application_Flavor_v2.1_TPM2.0-96bf10eb-0349-4449-9c4d-1eaa02560242"
                        }
                    ]
                },
                {
                    "pcr": {
                        "index": 17,
                        "bank": "SHA256"
                    },
                    "tpm_events": [
                        {
                            "measurement": "5d0220ffbceca9ca4e28215480c0280b1681328326c593743fa183f70ffbe834",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["HASH_START"],
                            "type_name": "HASH_START"
                        },
                        {
                            "measurement": "893d8ebf029907725f7deb657e80f7589c4ee52cdffed44547cd315f378f48c6",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["BIOSAC_REG_DATA"],
                            "type_name": "BIOSAC_REG_DATA"
                        },
                        {
                            "measurement": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["CPU_SCRTM_STAT"],
                            "type_name": "CPU_SCRTM_STAT"
                        },
                        {
                            "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["LCP_CONTROL_HASH"],
                            "type_name": "LCP_CONTROL_HASH"
                        },
                        {
                            "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["LCP_DETAILS_HASH"],
                            "type_name": "LCP_DETAILS_HASH"
                        },
                        {
                            "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["STM_HASH"],
                            "type_name": "STM_HASH"
                        },
                        {
                            "measurement": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["OSSINITDATA_CAP_HASH"],
                            "type_name": "OSSINITDATA_CAP_HASH"
                        },
                        {
                            "measurement": "5189168ddf098fa21f3d2159c629a76e43129d816c046d129d85a896d93044ed",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["MLE_HASH"],
                            "type_name": "MLE_HASH"
                        },
                        {
                            "measurement": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["NV_INFO_HASH"],
                            "type_name": "NV_INFO_HASH"
                        },
                        {
                            "measurement": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["tb_policy"],
                            "type_name": "tb_policy"
                        },
                        {
                            "measurement": "d4b319df2b01841ab98398dca33d8fcefcada45c40456711fa9b8551cf832649",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["vmlinuz"],
                            "type_name": "vmlinuz"
                        },
                        {
                            "measurement": "18b14d686f1782342e010a34de86c266421e6370a9e66260dfdd24fb884bb8aa",
							"type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
							"tags" :["initrd"],
                            "type_name": "initrd"
                        }
                    ]
                },
                {
                    "pcr": {
                        "index": 18,
                        "bank": "SHA256"
                    },
                    "tpm_events": [
                        {
                            "measurement": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "SINIT_PUBKEY_HASH"
                        },
                        {
                            "measurement": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "CPU_SCRTM_STAT"
                        },
                        {
                            "measurement": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "OSSINITDATA_CAP_HASH"
                        },
                        {
                            "measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "LCP_CONTROL_HASH"
                        },
                        {
                            "measurement": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "LCP_AUTHORITIES_HASH"
                        },
                        {
                            "measurement": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "NV_INFO_HASH"
                        },
                        {
                            "measurement": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
                            "type_id": "com.intel.mtwilson.core.common.model.MeasurementSha256",
                            "type_name": "tb_policy"
                        }
                    ]
                }
            ]
        }
    },
    "binding_key_certificate": "MIIFIDCCA4igAwIBAgIIJGn+rrG3xkwwDQYJKoZIhvcNAQEMBQAwGzEZMBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpazAeFw0yMDA5MTYwNjU5MjZaFw0zMDA5MTQwNjU5MjZaMCUxIzAhBgNVBAMMGkNOPUJpbmRpbmdfS2V5X0NlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0eIVvCegCxhcqqsK0ElkpFRhBjwrHDqUH4xAVaT76mWu2Xa8qcQcwnMQ801EjQPp9Zvo9yVscHxW4Ty0tGBrDKxb+oj/dC79d5yR3Q58JdLSsFPaPe70g/PBGs/+HU9Bj3+BrQpyIyGw/IrNDJnUDQv8D+OaTpa5AjxUFvP0anbvERpa94uF/3BlrdjY4d35CWDxPJncfYkWF8+ludAP+RkBDE3Wb1IqYH6k/cvAs7h/X3Rn9IPtEw6Jm1Vl3Qxl/SwkWMrAGj846GNBtv4Sj/GYGocucZg96MELdmwSkOPImIpl1Ypa+9zQM1+gJzScFQW5Rd7dFGQNWi1lDa8IuQIDAQABo4IB3DCCAdgwDgYDVR0PAQH/BAQDAgUgMIGdBgdVBIEFAwIpBIGR/1RDR4AXACIAC7Cet0n7o3OAeLMy+mi3q6WECH+E3WYQ/5c8iZIGAzcxAAQA/1WqAAAAAhjgiyMAAAA2AAAAAQEABwA+AAw2AAAiAAtsK5iQDs5MG3RH2oJJx/vtjBQHCs8KUI0AGFA/RRvhoQAiAAuFczKfXxkTGuYwZl2Ml9TiBW7EEW4Yh01hvgZgvIInbzCCARQGCFUEgQUDAikBBIIBBgAUAAsBAJgExcr7DCHZqSkGEMJkLXeUMOw2Xj9ReVGWYDhBKzxs/6mFE0/sx5e3NpkjKjmm2Bj50lM1CUtREnilkQiLNQsjGV1bpIDsOoL+NpZRFxcz/efKMAMCBk/YUjxqJ7EmkecnJ/H87JIwgSCpItYqU97Md4B/HP7Wd1Zd0nzxH3rXpe/meqwx3D9ifVqVSDPQB9ffAEmZ6MpnukC1x6twKvA6eAjkQDjjyiPeny8lCI8zdUM79iVrgCBYjLB7D1swEHj88nAsagilriCSrARoX48hbuN7/j5/+cZPAp82ca24d95anVwtJHWJPqhDEgzmYU4HsSs6AW6G291MeP635TAwDgYIVQSBBQMCKQIEAgAAMA0GCSqGSIb3DQEBDAUAA4IBgQA8EfaYI7Z4PaQYU9MX1nGDU5afOmY22DARRJAksi2TdC1CpVwmkO9kmtbnxIstTdNpXf5ZYdvHq+aMc6TBmzi/yidRLVOsLZum/BRn3k17efqBn4DUZnRsxHFjEy+MME9B2HWwzE4FVJ/Nyv99Ebd81PSTZjW5jCoPprYvIs4ffR8Ntmc5sRqU9pQ/nvSg9kqAbcfNF5rEAGDZM0s0QST4A05ID1B6L+Do8g2Ne8cqllv55U4dO5yEOsw+FoKTCin5r49+ajaUZyt1R3n4nkFvw9LC3uI11b8Wq/kFWMn+Ias7najaP2/9MndrkRM3cDOKW1ZqI4BT7FeUV1eepaEBK9oOTrhtNDLUiEtvrCu1DjH2v0v/MR0EcJKUWp62fsCsVzHveMaIegd9wtDG767JC+UxLgk2rh39C2vmQJobvIHxJlC6bOZKRPMsPonQjObB5QDeKuSv/bta7O0oaUs7kwgf3cRHkKaTpzTGtj6gm3BgBmU3Rb2fasltb0OO+lc=",
    "measurement_xmls": [
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Workload_Flavor_v2.1\" Uuid=\"3cdaa538-7816-419a-81c8-9e86d1a3b51f\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/workload-agent/bin\">e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a</Dir><File Path=\"/opt/workload-agent/bin/wlagent\">dd6a03766621e638bea300bf65ea1bab863110d976f6f7f21745e00f33c30dd13cc8af6dd55cabe063ad43789478802d</File><File Path=\"/opt/workload-agent/secure-docker-daemon/uninstall-container-security-dependencies.sh\">14de60e77324c680bee1b860463f8a793a4982b670b543908df667fc5b4f10d17c7f85d89aef84c6e844b5a2f5a8f6aa</File><CumulativeHash>51ee63bba9c2d0a85f6982c371ffb2afb925e04c262edc1f41e9b2e002e3b31a0e243fc5b887f9f22c7b6458291aa741</CumulativeHash></Measurement>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Application_Flavor_v2.1_TPM2.0\" Uuid=\"96bf10eb-0349-4449-9c4d-1eaa02560242\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/bin\">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/dracut_files\">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/initrd_hooks\">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/lib\">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/mkinitrd_files\">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir><File Path=\"/opt/tbootxm/bin/tpmextend\">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File><File Path=\"/opt/tbootxm/bin/measure\">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File><File Path=\"/opt/tbootxm/bin/configure_host.sh\">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File><File Path=\"/opt/tbootxm/bin/generate_initrd.sh\">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File><File Path=\"/opt/tbootxm/bin/measure_host\">63648dde7ef979e0ce32fbb4fc2087bf861ca0c9a2755d13e2135eaecf37e9e43e7523ac923d8073b0fe6159da6aba4a</File><File Path=\"/opt/tbootxm/bin/tboot-xm-uninstall.sh\">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File><File Path=\"/opt/tbootxm/bin/functions.sh\">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File><File Path=\"/opt/tbootxm/dracut_files/check\">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File><File Path=\"/opt/tbootxm/dracut_files/install\">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File><File Path=\"/opt/tbootxm/dracut_files/module-setup.sh\">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File><File Path=\"/opt/tbootxm/initrd_hooks/tcb\">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File><File Path=\"/opt/tbootxm/lib/libwml.so\">56a04d0f073f0eb2a4f851ebcba79f7080553c27fa8d1f7d4a767dc849015c9cc6c9abe937d0e90d73de27814f28e378</File><File Path=\"/opt/tbootxm/lib/create_menuentry.pl\">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File><File Path=\"/opt/tbootxm/lib/update_menuentry.pl\">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File><File Path=\"/opt/tbootxm/lib/remove_menuentry.pl\">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File><File Path=\"/opt/tbootxm/mkinitrd_files/setup-measure_host.sh\">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/trustagent/bin\">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir><File Path=\"/opt/trustagent/bin/tagent\">14de1f422595a231b4efc8c64a9fd5cfb7952182371b7856b4909864287f6eb62fed839f11b043948c39e238c61197cd</File><File Path=\"/opt/trustagent/bin/module_analysis.sh\">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File><File Path=\"/opt/trustagent/bin/module_analysis_da.sh\">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File><File Path=\"/opt/trustagent/bin/module_analysis_da_tcg.sh\">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File><CumulativeHash>1cb7f7d37adf57274620d44e687ffc9a184cd5ab5c5e434b30514241198b6ecbd029e2ab78072540b875f52d304bc042</CumulativeHash></Measurement>"
    ]
}`

var hostManifestString = `{
	"aik_certificate": "MIIDUDCCAbigAwIBAgIQXO/rJ3odoWWFGFfhlkksOjANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDExdIVlMgUHJpdmFjeSBDZXJ0aWZpY2F0ZTAeFw0yMDEwMzAxMTU3MDRaFw0yNTEwMzAxMTU3MDRaMCIxIDAeBgNVBAMTF0hWUyBQcml2YWN5IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4txj1hsEFJGgRSoP214Vsly8TFryPBj5YeQNUlOHze0JdQ9sDw4CN3LTneOa36UWz57omrITiXNKc96aN6TEEh2hn1ACZd0jRHXWrVr8n0gq3ZPQLgIZREAlBvK967n+O2Aybq1QPqV4KV3Ry51ood0rDhFUqDtItkjbVRsejBAk0lxT6iUmHHMrmrxbINfzjYjKPfQ/Rcw3h+QTBKlglgF5qy9mv+DoRf1AWtre79qWikfxnhkX2O11rRqT9hj9zJn4xMRKVerjbkeC8rt/9dSa0fOtt+jHdWymNDGjseWfBSp16vQRSl7UdITyadLA0b8O/+DufAF2sedEhOTcWQIDAQABowIwADANBgkqhkiG9w0BAQsFAAOCAYEApwirFXwihLm0WAGeyFUeRWjlQ0VQ01KKmyzw1yZt+JWkq2r/Mi+Iet61AUnXO1aVwIfi9g/79i7x/T7H4rxfyUfnHEXw+9AMGzFrSHsQNtBOksc1M/uBKXtM8A4Nihs+pEdtvHR0uYnasoJk/KXvauYtk2cdfeIjK7eLZC3HknMcig8ujMOHpeSUrFasxvNOomvnV3HXru96hd4WQyq9lFfC24iC1vFDm+4TlgjuVy+0PVLpEhKKvtxl6rVXCqD7eyTZfxsRoXkGJWMzpaX3izDeR/uoKS1HFMvLEX7SNM+5G5UvNoja15Zof/KaViyMPgjDYYFWI3gPC2Y4WFU9ya17n1a3wpmmh3x1H8u/lzOPdcmMTwAK8CeGwjhJkPCP/h9mJgQjGnmoajI2R8R0aDTNye1EfUMKNP+ZDKFR9c3lPnv+MPoHhCiMHytmRqZDkJAzhc5lGeYyT1q/8mMyebNQO5+zWnZtV7t0NhvB6W8diyg3BssBkYV4vLHnt9q5",
	"host_info": {
		"os_name": "RedHatEnterprise",
		"vendor": "Linux",
		"tpm_version": "2.0",
		"uefi_enabled": "true",
		"suefi_enabled": "true",
		"os_version": "8.1",
		"bios_version": "SE5C620.86B.00.01.0014.070920180847",
		"vmm_name": "",
		"vmm_version": "",
		"processor_info": "54 06 05 00 FF FB EB BF",
		"host_name": "localhost.localdomain",
		"bios_name": "Intel Corporation",
		"hardware_uuid": "800012a7-669d-e811-906e-00163566263e",
		"process_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
		"no_of_sockets": "2",
		"hardware_features": {
			"TXT": {
				"enabled": "true"
			},
			"TPM": {
				"enabled": "true",
				"meta": {
					"tpm_version": "2.0",
					"pcr_banks": "SHA1_SHA256"
				}
			},
			"SUEFI": {
				"enabled": "true"
			}
		},
		"installed_components": [
			"tagent",
			"wlagent"
		]
	},
	"pcr_manifest": {
		"sha1pcrs": [
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_0",
				"value": "3f95ecbb0bb8e66e54d3f9e4dbae8fe57fed96f0",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_1",
				"value": "12534a75d3827c49957211df39f633996552960a",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_2",
				"value": "a196e9d4b283700303db501ed7279af6ec417e2d",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_3",
				"value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_4",
				"value": "b9f6508122aa0ec0d9a9bf51848303fdadcede91",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_5",
				"value": "9f2b569c104ed505a7d6abb7be2d4ae6b1a59a16",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_6",
				"value": "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_7",
				"value": "e377797356c0ee1b01810b303976d13a5e6abf2f",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_8",
				"value": "bdc4abc3685aa30a2d80733605d66728526d908f",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_9",
				"value": "baa9af2d3d1676fe2452b9ac72655b8ce7e33cc6",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_10",
				"value": "9c4ba173ef7010e71e982c9e37b0d12e0a442d5d",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_11",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_12",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_13",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_14",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_15",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_16",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_17",
				"value": "ffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_18",
				"value": "ffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_19",
				"value": "ffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_20",
				"value": "ffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_21",
				"value": "ffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_22",
				"value": "ffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA1"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha1",
				"index": "pcr_23",
				"value": "0000000000000000000000000000000000000000",
				"pcr_bank": "SHA1"
			}
		],
		"sha2pcrs": [
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_0",
				"value": "1009d6bc1d92739e4e8e3c6819364f9149ee652804565b83bf731bdb6352b2a6",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_1",
				"value": "90b00bb336330fb902194b3ee5d6aa637cb234bd9ae1f0f4049480d5b0aba0f5",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_2",
				"value": "0033ef74f1d62b9d95c641bfda24642bafb7a6b54d03d90655d7c5f9b1d47caf",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_3",
				"value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_4",
				"value": "a5405815905f0bc17547d1accb40819de3ba304b1c8e599e606c15d837eb2ad6",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_5",
				"value": "0d18b2246909b11458dd05c1a13228c5227704c27f0324bfe346890cbbdcf688",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_6",
				"value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_7",
				"value": "a2aa16e5924a6e15e60b3fc10b911f78b155c3223afeda7f5451bd42ce48f8f5",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_8",
				"value": "2d854e9844940c94dc20ec00c8836194f5efe3cc7bd27502c93f819d723cfe68",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_9",
				"value": "ef9545f11dc771571cc2003486041dd2504f3e997d79dc1e0d57a8c6c7beb0c7",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_10",
				"value": "7faf3e79aaf67f38ae4ccf536655ccbacf3ebdc005118cefede9538b450b112d",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_11",
				"value": "0000000000000000000000000000000000000000000000000000000000000000",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_12",
				"value": "0000000000000000000000000000000000000000000000000000000000000000",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_13",
				"value": "0000000000000000000000000000000000000000000000000000000000000000",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_14",
				"value": "0000000000000000000000000000000000000000000000000000000000000000",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_15",
				"value": "9521bd4eee34cece057dfe8247c92f0a0c2a8d95beee5155380f3e9dfb1b7992",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_16",
				"value": "0000000000000000000000000000000000000000000000000000000000000000",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_17",
				"value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_18",
				"value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_19",
				"value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_20",
				"value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_21",
				"value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_22",
				"value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"pcr_bank": "SHA256"
			},
			{
				"digest_type": "com.intel.mtwilson.core.common.model.PcrSha256",
				"index": "pcr_23",
				"value": "0000000000000000000000000000000000000000000000000000000000000000",
				"pcr_bank": "SHA256"
			}
		],
		"pcr_event_log_map": {
			"SHA1":[
				{
				   "pcr ":{
					  "index":0,
					  "bank":"SHA1"
				   },
				   "tpm_event":[
					  {
						 "type_id":1238,
						 "type_name":"EV_EFI_PLATFORM_FIRWARE_BLOB2",
						 "tags":[
							"Firmware_IDE"
						 ],
						 "measurement":"902ee834225fb5e3304bf52184823f767dd9ba2cc7f67479633ea9f95ce51528"
					  },
					  {
						 "type_id":1234,
						 "type_name":"EV_EFI_VARIABLE_BOOT2",
						 "tags":[
							"Hash"
						 ],
						 "measurement":"902ee834225fb5e3304bf52184823f767dd9ba2cc7f67479633ea9f95ce51528"
					  }
				   ]
				}
			 ],
			 "SHA256":[
				{
				   "pcr":{
					  "index":0,
					  "bank":"SHA256"
				   },
				   "tpm_event":[
					  {
						 "type_id":12345,
						 "type_name":"EV_EFI_PLATFORM_FIRWARE_BLOB2",
						 "tags":[
							"shim"
						 ],
						 "measurement":"902ee834225fb5e3304bf52184823f767dd9ba2cc7f67479633ea9f95ce51528"
					  },
					  {
						 "type_id":123456,
						 "type_name":"EV_EFI_VARIABLE_BOOT2",
						 "tags":[
							"Firmware Hash"
						 ],
						 "measurement":"902ee834225fb5e3304bf52184823f767dd9ba2cc7f67479633ea9f95ce51528"
					  }
				   ]
				},
				{
				   "pcr":{
					  "index":7,
					  "bank":"SHA256"
				   },
				   "tpm_event":[
					  {
						 "type_id":1234567,
						 "type_name":"EV_EFI_VARIABLE_AUTHORITY",
						 "tags":[
							"shim"
						 ],
						 "measurement":"a8b191c7191fe51..."
					  },
					  {
						 "type_id":12344567,
						 "type_name":"EV_EFI_PLATFORM_FIRWARE_BLOB2",
						 "tags":[
							"AMI/BMC"
						 ],
						 "measurement":"91b63d8f261251..."
					  }
				   ]
				}
			 ]
		  }
	},
	"binding_key_certificate": "MIIFHDCCA4SgAwIBAgIRAesEjU6Bco4NxLzGmvP6UfwwDQYJKoZIhvcNAQEMBQAwIjEgMB4GA1UEAxMXSFZTIFByaXZhY3kgQ2VydGlmaWNhdGUwHhcNMjAxMDMwMTI1NDQ4WhcNMzAxMDMwMTI1NDQ4WjAiMSAwHgYDVQQDDBdCaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASEwDQYJKoZIhvcNAQEBBQADggEOADCCAQkCggEBAMrvvM9nHCHalpNgWqOZwf3zf5rxp73CAsq5B4xs27duCeBQ4TUvENrft+xNkkK89hWaS52Ii1eTWm8uw0ESbiYcAmSUAeqKvtqlSDtLm720lLUmg1FoACHMNTv+U/8SI4q1TeMyGqvkvK8fVifiZSlqUdVSjSACB925UMsQ5XBh8QlIUuEiRPHoUo18AQL1qcNR3NCDvO2arE+Tys7U7Xu036UvR3VKYpZ9rEYRkX2tk5b8wSup2Ts2Bvg3oV69EW5xUdSdn1RZ/BG+JuP4Ijr6PEY5huaNwQte/jS9vM/xqoQjhNbVzFFQxT6fyiP2ezPUunw5uzx2RItPr0SBhcECAgEAo4IBzDCCAcgwDgYDVR0PAQH/BAQDAgWgMIGdBgdVBIEFAwIpBIGR/1RDR4AXACIAC1q7ZptELyLKQghJS3mDkNECshLzlRm5DX5zZQY5Y/5MAAQA/1WqAAAAAAFvzsAAAAAIAAAAAAEABwA+AAw2AAAiAAt2hFXY1d0s/NPbM56TyVFfNN1lZXSGhLM5g6hzPkP9aQAiAAv9BhIdEV1oMuDL+S6GNZ8ibh7A1DW1O3VVDc1OFewg+DCCARQGCFUEgQUDAikBBIIBBgAUAAsBAKDdrdD3qwUU28zsip95qiJcUAQKcjMlKZLxLtocsVWjd1HuWsNTS90snVnRKcbJRmpnF5dzWtTO861pVbaVot02ccEED/wQ5rBvwPXfcC5rAv3vpePpjxgPfzq1QrF6QeTsfT+EiLLVr1s3mfuja6gr8918IPv/cAfWxIk+Cy1xS8F1aLrEweSBcFHf2jaSlGaYDMQHfNYTRE08el/J9kgSy+aY8dIXSsZov5C3QXVM6KkgPMZjPs/4U93eLO3W3tgVolM2/aZBY07E2mQqFlKtJ8sgLpKf0A8EmHZ6avXw7TGOwGprqUuVdYt3+/O+Z0IxWpYUVx+YB6bSNz5jT78wDQYJKoZIhvcNAQEMBQADggGBAJjzdDwHUm8hiWtgMwCp0khMHSCbNmXzLuKHQSePEVfaGGcq23OSQrRI/b7Ov+BDjksPIk+iLfEuzIYsxkUuG4KAtFsfZh/aSDmxb66CDR1N6rNTfhuNBLMLeqUMfE7PNJIOi0Bdp9LCc2bP5sOFbXgF28QEsJx4zcYWbHCalaxdjWyYCaRnhTacuVCec01R/buEDG2342DxzR/dJtA8b/2jm6FyhvLpzk/+bDRFnAgxCEfYTk7tdi8s5AgLLG2x54wxulJyNOvuu0L1rlSKpaAcZEXq/zlusxMEBSFHR8Bu/xU2qbxFB86QZU9vRl9uIxTOeEV5n1E2UBxy7V+KBi1ixKbnMePJgMK0AtPRgxDmVyuu4XmpA63zNtH/uLUAFfbp3xqE5xjd6Ioqyef/I6vttZ8GFrn0v24UVcC9gZhdPeIaBxIJVtXMuobwBGm1kc5flPfbQPDpZOX/aH60hxN+wegwckE82u0mNjOC4tMiarwKGwN/ILHdWNeUs8pePw==",
	"measurement_xmls": [
		"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Workload_Flavor_v2.1\" Uuid=\"6ddd0a43-736c-4369-abfd-9a1e22a9b735\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/workload-agent/bin\">e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a</Dir><File Path=\"/opt/workload-agent/bin/wlagent\">dd6a03766621e638bea300bf65ea1bab863110d976f6f7f21745e00f33c30dd13cc8af6dd55cabe063ad43789478802d</File><CumulativeHash>c2b9cef7437ae661d84d04fc8d9ddfa3fb45ce28cdb555f0ba355cf035181afd8de3b928185a49d48786fecc1bc9193f</CumulativeHash></Measurement>",
		"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Measurement xmlns=\"lib:wml:measurements:1.0\" Label=\"ISecL_Default_Application_Flavor_v2.1_TPM2.0\" Uuid=\"a2c616e0-9ace-4dab-adbc-1d10b8cbeb4a\" DigestAlg=\"SHA384\"><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/bin\">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/dracut_files\">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/initrd_hooks\">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/lib\">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/tbootxm/mkinitrd_files\">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir><File Path=\"/opt/tbootxm/bin/tpmextend\">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File><File Path=\"/opt/tbootxm/bin/measure\">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File><File Path=\"/opt/tbootxm/bin/configure_host.sh\">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File><File Path=\"/opt/tbootxm/bin/generate_initrd.sh\">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File><File Path=\"/opt/tbootxm/bin/measure_host\">63648dde7ef979e0ce32fbb4fc2087bf861ca0c9a2755d13e2135eaecf37e9e43e7523ac923d8073b0fe6159da6aba4a</File><File Path=\"/opt/tbootxm/bin/tboot-xm-uninstall.sh\">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File><File Path=\"/opt/tbootxm/bin/functions.sh\">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File><File Path=\"/opt/tbootxm/dracut_files/check\">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File><File Path=\"/opt/tbootxm/dracut_files/install\">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File><File Path=\"/opt/tbootxm/dracut_files/module-setup.sh\">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File><File Path=\"/opt/tbootxm/initrd_hooks/tcb\">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File><File Path=\"/opt/tbootxm/lib/libwml.so\">56a04d0f073f0eb2a4f851ebcba79f7080553c27fa8d1f7d4a767dc849015c9cc6c9abe937d0e90d73de27814f28e378</File><File Path=\"/opt/tbootxm/lib/create_menuentry.pl\">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File><File Path=\"/opt/tbootxm/lib/update_menuentry.pl\">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File><File Path=\"/opt/tbootxm/lib/remove_menuentry.pl\">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File><File Path=\"/opt/tbootxm/mkinitrd_files/setup-measure_host.sh\">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File><Dir Exclude=\"\" Include=\".*\" Path=\"/opt/trustagent/bin\">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir><File Path=\"/opt/trustagent/bin/tagent\">14de1f422595a231b4efc8c64a9fd5cfb7952182371b7856b4909864287f6eb62fed839f11b043948c39e238c61197cd</File><File Path=\"/opt/trustagent/bin/module_analysis.sh\">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File><File Path=\"/opt/trustagent/bin/module_analysis_da.sh\">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File><File Path=\"/opt/trustagent/bin/module_analysis_da_tcg.sh\">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File><CumulativeHash>1cb7f7d37adf57274620d44e687ffc9a184cd5ab5c5e434b30514241198b6ecbd029e2ab78072540b875f52d304bc042</CumulativeHash></Measurement>"
	]
}`

func NewFlavorController(fs domain.FlavorStore, fgs domain.FlavorGroupStore, hs domain.HostStore, tcs domain.TagCertificateStore, htm domain.HostTrustManager, certStore *dm.CertificatesStore, hcConfig domain.HostControllerConfig, fts domain.FlavorTemplateStore) *FlavorController {
	// certStore should have an entry for Flavor Signing CA
	if _, found := (*certStore)[dm.CertTypesFlavorSigning.String()]; !found {
		defaultLog.Errorf("controllers/flavor_controller:NewFlavorController() %s : Flavor Signing KeyPair not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	var fsKey crypto.PrivateKey
	fsKey = (*certStore)[dm.CertTypesFlavorSigning.String()].Key
	if fsKey == nil {
		defaultLog.Errorf("controllers/flavor_controller:NewFlavorController() %s : Flavor Signing Key not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	hController := HostController{
		HStore:   hs,
		HCConfig: hcConfig,
	}

	return &FlavorController{
		FStore:    fs,
		FGStore:   fgs,
		HStore:    hs,
		TCStore:   tcs,
		HTManager: htm,
		CertStore: certStore,
		HostCon:   hController,
		FTStore:   fts,
	}
}

func (fcon *FlavorController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Create() Leaving")

	flavorCreateReq, err := getFlavorCreateReq(r)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Content-Type") {
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// validate permissions for each flavorPart
	privileges, err := comctx.GetUserPermissions(r)
	if err != nil {
		secLog.Errorf("flavor_controller:Create() %s", commLogMsg.AuthenticationFailed)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Could not get user permissions from http context"}
	}

	var signedFlavors []hvs.SignedFlavorFC

	if len(flavorCreateReq.FlavorParts) == 0 {
		if !checkValidFlavorPermission(privileges, []string{consts.FlavorCreate}) {
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
		}
	} else {
		for _, fp := range flavorCreateReq.FlavorParts {
			if fp == fc.FlavorPartHostUnique {
				if !checkValidFlavorPermission(privileges, []string{consts.HostUniqueFlavorCreate, consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			} else if fp == fc.FlavorPartSoftware {
				if !checkValidFlavorPermission(privileges, []string{consts.SoftwareFlavorCreate, consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			} else if fp == fc.FlavorPartAssetTag {
				if !checkValidFlavorPermission(privileges, []string{consts.TagFlavorCreate, consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			} else {
				if !checkValidFlavorPermission(privileges, []string{consts.FlavorCreate}) {
					return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Insufficient privileges to access /v2/hvs/flavors"}
				}
			}
		}
	}

	signedFlavors, err = fcon.createFlavors(flavorCreateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Create() Error creating flavors")
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor with same id/label already exists"}
		}
		if strings.Contains(err.Error(), "401") {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Authentication with trust agent failed"}
		}
		if strings.Contains(err.Error(), "403") {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Authorization with trust agent failed"}
		}
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error creating flavors, error connecting to trust agent"}
	}

	signedFlavorCollection := hvs.SignedFlavorCollectionFC{
		SignedFlavors: signedFlavors,
	}
	// // Reorder flavors as per request
	// if flavorCreateReq.FlavorParts != nil && len(flavorCreateReq.FlavorParts) > 0 {
	// 	signedFlavorCollection = orderFlavorsPerFlavorParts(flavorCreateReq.FlavorParts, signedFlavorCollection)
	// }
	secLog.Info("Flavors created successfully")
	return signedFlavorCollection, http.StatusCreated, nil
}

func (fcon *FlavorController) createFlavors(flavorReq dm.FlavorCreateRequest) ([]hvs.SignedFlavorFC, error) {
	defaultLog.Trace("controllers/flavor_controller:createFlavors() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createFlavors() Leaving")

	var flavorParts []fc.FlavorPart
	var platformFlavor *fType.PlatformFlavor
	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavorFC)

	if flavorReq.ConnectionString != "" {
		// get flavor from host
		// get host manifest from the host
		defaultLog.Debug("Host connection string given, trying to create flavors from host")
		/*connectionString, _, err := GenerateConnectionString(flavorReq.ConnectionString,
		fcon.HostCon.HCConfig.Username,
		fcon.HostCon.HCConfig.Password,
		fcon.HostCon.HCStore)*/

		/*if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Could not generate formatted connection string")
			return nil, errors.Wrap(err, "Error while generating a formatted connection string")
		}
		defaultLog.Debug("Getting manifest from host...")
		hostManifest, err := fcon.getHostManifest(connectionString)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Error getting host manifest")
			return nil, errors.Wrap(err, "Error getting host manifest")
		}*/

		//flavorTemplates, err := fcon.findTemplatesToApply(hostManifest)
		var hostManifest *hcType.HostManifest                  // temp code
		flavorTemplates, err := fcon.findTemplatesToApply(nil) // temp code
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Error in finding the templates to apply")
			return nil, errors.Wrap(err, "Error getting host manifest")
		}
		defaultLog.Info("********************flavor_templates********************")
		defaultLog.Info(flavorTemplates)
		defaultLog.Info("********************")

		// tagCertificate := hvs.TagCertificate{}
		// var tagX509Certificate *x509.Certificate
		// tcFilterCriteria := dm.TagCertificateFilterCriteria{
		// 	HardwareUUID: uuid.MustParse(hostManifest.HostInfo.HardwareUUID),
		// }
		// tagCertificates, err := fcon.TCStore.Search(&tcFilterCriteria)
		// if err != nil {
		// 	defaultLog.Debugf("Unable to retrieve tag certificate for host with hardware UUID %s", hostManifest.HostInfo.HardwareUUID)
		// }
		// if len(tagCertificates) >= 1 {
		// 	tagCertificate = *tagCertificates[0]
		// 	tagX509Certificate, err = x509.ParseCertificate(tagCertificate.Certificate)
		// 	if err != nil {
		// 		defaultLog.Errorf("controllers/flavor_controller: Failed to parse x509.Certificate from tag certificate for host with hardware UUID %s", hostManifest.HostInfo.HardwareUUID)
		// 		return nil, errors.Wrapf(err, "Failed to parse x509.Certificate from tag certificate for host with hardware UUID %s", hostManifest.HostInfo.HardwareUUID)
		// 	}
		// 	defaultLog.Debugf("Tag attribute certificate exists for the host with hardware UUID: %s", hostManifest.HostInfo.HardwareUUID)
		// }

		var hostManifestFC *hcType.HostManifestFC
		err = json.Unmarshal([]byte(steffyHostManifest), &hostManifestFC)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Error in Unmarshal the host manifest")
			return nil, err
		}

		// create a platform flavor with the host manifest information
		defaultLog.Debug("Creating flavor from host manifest using flavor library")
		newPlatformFlavor, err := flavor.NewPlatformFlavorProvider(nil, hostManifestFC, nil, flavorTemplates)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:createFlavors() Error while creating platform flavor instance from host manifest and tag certificate")
			return nil, errors.Wrap(err, "Error while creating platform flavor instance from host manifest and tag certificate")
		}

		platformFlavor, err = newPlatformFlavor.GetPlatformFlavor()
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:createFlavors() Error while creating platform flavors for host %s", hostManifest.HostInfo.HardwareUUID)
			return nil, errors.Wrapf(err, " Error while creating platform flavors for host %s", hostManifest.HostInfo.HardwareUUID)
		}
		// add all the flavor parts from create request to the list flavor parts to be associated with a flavorgroup
		if len(flavorReq.FlavorParts) >= 1 {
			for _, flavorPart := range flavorReq.FlavorParts {
				flavorParts = append(flavorParts, flavorPart)
			}
		}

	}
	// else if len(flavorReq.FlavorCollection.Flavors) >= 1 || len(flavorReq.SignedFlavorCollection.SignedFlavors) >= 1 {
	// 	defaultLog.Debug("Creating flavors from flavor content")
	// 	flavorSignKey, _, _ := (*fcon.CertStore).GetKeyAndCertificates(dm.CertTypesFlavorSigning.String())

	// 	// create flavors from flavor content
	// 	// TODO: currently checking only the unsigned flavors
	// 	for _, flavor := range flavorReq.FlavorCollection.Flavors {
	// 		// TODO : check if BIOS flavor part name is still accepted, if it is update the flavorpart to PLATFORM
	// 		defaultLog.Debug("Validating flavor meta content for flavor part")
	// 		if err := validateFlavorMetaContent(&flavor.Flavor.Meta); err != nil {
	// 			defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor content must be given, invalid flavor meta data")
	// 			return nil, errors.Wrap(err, "Invalid flavor content")
	// 		}
	// 		// get flavor part form the content
	// 		var fp fc.FlavorPart
	// 		if err := (&fp).Parse(flavor.Flavor.Meta.Description.FlavorPart); err != nil {
	// 			defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor part must be given")
	// 			return nil, errors.Wrap(err, "Error parsing flavor part")
	// 		}
	// 		// check if flavor part already exists in flavor-flavorPart map, else sign the flavor and add it to the map
	// 		var platformFlavorUtil fu.PlatformFlavorUtil

	// 		defaultLog.Debug("Signing the flavor content")
	// 		signedFlavor, err := platformFlavorUtil.GetSignedFlavorFC(&flavor.Flavor, flavorSignKey.(*rsa.PrivateKey))
	// 		if err != nil {
	// 			defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting signed flavor from flavor library")
	// 			return nil, errors.Wrap(err, "Error getting signed flavor from flavor library")
	// 		}

	// 		if _, ok := flavorFlavorPartMap[fp]; ok {
	// 			// sign the flavor and add it to the same flavor list
	// 			flavorFlavorPartMap[fp] = append(flavorFlavorPartMap[fp], *signedFlavor)
	// 		} else {
	// 			// add the flavor to the new list
	// 			flavorFlavorPartMap[fp] = []hvs.SignedFlavorFC{*signedFlavor}
	// 		}
	// 		flavorParts = append(flavorParts, fp)
	// 	}
	// 	if len(flavorFlavorPartMap) == 0 {
	// 		defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor content must be given")
	// 		return nil, errors.New("Valid flavor content must be given")
	// 	}
	// }
	var err error
	// add all flavorparts to default flavorgroups if flavorgroup name is not given
	if flavorReq.FlavorgroupNames == nil && len(flavorReq.FlavorParts) == 0 {
		for _, flavorPart := range fc.GetFlavorTypes() {
			flavorParts = append(flavorParts, flavorPart)
		}
	}
	// get the flavorgroup names
	if len(flavorReq.FlavorgroupNames) == 0 {
		flavorReq.FlavorgroupNames = []string{dm.FlavorGroupsAutomatic.String()}
	}
	// check if the flavorgroup is already created, else create flavorgroup
	flavorgroups, err := CreateMissingFlavorgroups(fcon.FGStore, flavorReq.FlavorgroupNames)
	if err != nil {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting flavorgroups")
		return nil, err
	}

	// if platform flavor was retrieved from host, break it into the flavor part flavor map using the flavorgroups
	if platformFlavor != nil {
		flavorFlavorPartMap = fcon.retrieveFlavorCollectionFC(platformFlavor, flavorgroups, flavorParts)
	}

	if flavorFlavorPartMap == nil || len(flavorFlavorPartMap) == 0 {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Cannot create flavors")
		return nil, errors.New("Unable to create Flavors")
	}
	return fcon.addFlavorToFlavorgroupFC(flavorFlavorPartMap, flavorgroups)
}

func getFlavorCreateReq(r *http.Request) (dm.FlavorCreateRequest, error) {
	defaultLog.Trace("controllers/flavor_controller:getFlavorCreateReq() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getFlavorCreateReq() Leaving")

	var flavorCreateReq dm.FlavorCreateRequest
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		secLog.Error("controllers/flavor_controller:getFlavorCreateReq() Invalid Content-Type")
		return flavorCreateReq, errors.New("Invalid Content-Type")
	}

	secLog.Infof("Request to create host_unique flavors received")
	if r.ContentLength == 0 {
		secLog.Error("controllers/flavor_controller:getFlavorCreateReq() The request body is not provided")
		return flavorCreateReq, errors.New("The request body is not provided")
	}

	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&flavorCreateReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_controller:getFlavorCreateReq() %s :  Failed to decode request body as Flavor", commLogMsg.InvalidInputBadEncoding)
		return flavorCreateReq, errors.New("Unable to decode JSON request body")
	}

	defaultLog.Debug("Validating create flavor request")
	err = validateFlavorCreateRequest(flavorCreateReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_controller:CreateFlavors() %s Invalid flavor create criteria", commLogMsg.InvalidInputBadParam)
		return flavorCreateReq, errors.New("Invalid flavor create criteria")
	}
	//Unique flavor parts
	flavorCreateReq.FlavorParts = fc.FilterUniqueFlavorParts(flavorCreateReq.FlavorParts)

	return flavorCreateReq, nil
}

func orderFlavorsPerFlavorParts(parts []fc.FlavorPart, signedFlavorCollection hvs.SignedFlavorCollection) hvs.SignedFlavorCollection {
	signedFlavors := []hvs.SignedFlavor{}
	for _, flavorPart := range parts {
		signedFlavors = append(signedFlavors, signedFlavorCollection.GetFlavors(flavorPart.String())...)
	}
	return hvs.SignedFlavorCollection{
		SignedFlavors: signedFlavors,
	}
}

func (fcon *FlavorController) getHostManifest(cs string) (*hcType.HostManifest, error) {
	defaultLog.Trace("controllers/flavor_controller:getHostManifest() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getHostManifest() Leaving")
	hostConnector, err := fcon.HostCon.HCConfig.HostConnectorProvider.NewHostConnector(cs)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}
	hostManifest, err := hostConnector.GetHostManifest()
	return &hostManifest, err
}

func (fcon *FlavorController) findTemplatesToApply(hostManifest *hcType.HostManifest) (*[]hvs.FlavorTemplate, error) {
	var filteredTemplates []hvs.FlavorTemplate
	flavorTemplates, err := fcon.FTStore.Search(false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Error retrieving all flavor templates")
		return nil, err
	}
	defaultLog.Info("************FlvrTemplates")
	defaultLog.Info(flavorTemplates)
	/*	bytes, err := json.Marshal(hostManifest)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Unable to marshal host manifest")
			return nil, err
		}
		hostManifestJson, err := jsonquery.Parse(strings.NewReader(string(bytes))) */

	hostManifestJson, err := jsonquery.Parse(strings.NewReader(string(steffyHostManifest))) // tempCode
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavortemplate_controller:Search() Error in parsing the host manifest")
		return nil, err
	}
	for _, flavorTemplate := range flavorTemplates {
		conditionEval := true
		defaultLog.Info("checkpoint A")
		for _, condition := range flavorTemplate.Condition {
			defaultLog.Info("checkpoint B")
			expectedData, _ := jsonquery.Query(hostManifestJson, condition)
			if expectedData == nil {
				conditionEval = false
				defaultLog.Info("**************False" + condition)
				break
			} else {
				defaultLog.Info("**************" + condition)
			}
		}
		if conditionEval == true {
			defaultLog.Info("**************Eval=true")
			filteredTemplates = append(filteredTemplates, flavorTemplate)
		}
	}

	return &filteredTemplates, nil
}

func (fcon *FlavorController) addFlavorToFlavorgroupFC(flavorFlavorPartMap map[fc.FlavorPart][]hvs.SignedFlavorFC, fgs []hvs.FlavorGroup) ([]hvs.SignedFlavorFC, error) {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Leaving")

	var returnSignedFlavors []hvs.SignedFlavorFC

	for _, signedFlavors := range flavorFlavorPartMap {

		defaultLog.Debug("Signed Flavor")
		defaultLog.Debugf("Flavor -> ", signedFlavors)
		returnSignedFlavors = signedFlavors
	}
	return returnSignedFlavors, nil
}

func (fcon *FlavorController) addFlavorToFlavorgroup(flavorFlavorPartMap map[fc.FlavorPart][]hvs.SignedFlavor, fgs []hvs.FlavorGroup) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Leaving")

	defaultLog.Debug("Adding flavors to flavorgroup")
	var returnSignedFlavors []hvs.SignedFlavor
	// map of flavorgroup to flavor UUID's to create the association
	flavorgroupFlavorMap := make(map[uuid.UUID][]uuid.UUID)
	var flavorgroupsForQueue []hvs.FlavorGroup
	fetchHostData := false
	var fgHostIds []uuid.UUID

	for flavorPart, signedFlavors := range flavorFlavorPartMap {
		defaultLog.Debugf("Creating flavors for fp %s", flavorPart.String())
		for _, signedFlavor := range signedFlavors {
			flavorgroups := []hvs.FlavorGroup{}
			signedFlavorCreated, err := fcon.FStore.Create(&signedFlavor)
			if err != nil {
				defaultLog.WithError(err).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : "+
					"Unable to create flavors of %s flavorPart", flavorPart.String())
				if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
					defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
						"Error cleaning up already existing flavors on flavor creation failure")
				}

				return nil, err
			}
			// if the flavor is created, associate it with an appropriate flavorgroup
			if signedFlavorCreated != nil && signedFlavorCreated.Flavor.Meta.ID.String() != "" {
				// add the created flavor to the list of flavors to be returned
				returnSignedFlavors = append(returnSignedFlavors, *signedFlavorCreated)
				if flavorPart == fc.FlavorPartAssetTag || flavorPart == fc.FlavorPartHostUnique {
					flavorgroup, err := fcon.createFGIfNotExists(dm.FlavorGroupsHostUnique.String())
					if err != nil || flavorgroup.ID == uuid.Nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Error getting host_unique flavorgroup")
						if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
							defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
								"Error cleaning up already existing flavors on flavor creation failure")
						}
						return nil, err
					}
					flavorgroupsForQueue = append(flavorgroupsForQueue, *flavorgroup)
					// get hostId
					var hostHardwareUUID uuid.UUID
					if !reflect.DeepEqual(signedFlavorCreated.Flavor.Meta, fm.Meta{}) &&
						!reflect.DeepEqual(signedFlavorCreated.Flavor.Meta.Description, fm.Description{}) &&
						signedFlavorCreated.Flavor.Meta.Description.HardwareUUID != nil {
						hostHardwareUUID = *signedFlavorCreated.Flavor.Meta.Description.HardwareUUID
					} else {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() hardware UUID must be specified in the flavor document")
						if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
							defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
								"Error cleaning up already existing flavors on flavor creation failure")
						}
						return nil, errors.New("hardware UUID must be specified in the HOST_UNIQUE flavor")
					}

					hosts, err := fcon.HStore.Search(&dm.HostFilterCriteria{
						HostHardwareId: hostHardwareUUID,
					})
					if len(hosts) == 0 || err != nil {
						defaultLog.Infof("Host with matching hardware UUID not registered")
					}
					for _, host := range hosts {
						// associate host unique flavors such as HOST_UNIQUE and ASSET_TAG with the hosts
						if _, err := fcon.HStore.AddHostUniqueFlavors(host.Id, []uuid.UUID{signedFlavorCreated.Flavor.Meta.ID}); err != nil {
							defaultLog.WithError(err).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : "+
								"Unable to associate %s flavorPart with host id : %v", flavorPart.String(), host.Id)
							return nil, errors.Wrap(err, "Unable to associate flavorPart with host id")
						}
						// add host to the list of host Id's to be added into flavor-verification queue
						fgHostIds = append(fgHostIds, host.Id)
					}
					if flavorPart == fc.FlavorPartAssetTag {
						fetchHostData = true
					}
					flavorgroups = []hvs.FlavorGroup{*flavorgroup}
				} else if flavorPart == fc.FlavorPartSoftware {
					var softwareFgName string
					addToNonSoftwareGroup := false
					if strings.Contains(signedFlavorCreated.Flavor.Meta.Description.Label, fConst.DefaultSoftwareFlavorPrefix) {
						softwareFgName = dm.FlavorGroupsPlatformSoftware.String()
					} else if strings.Contains(signedFlavorCreated.Flavor.Meta.Description.Label, fConst.DefaultWorkloadFlavorPrefix) {
						softwareFgName = dm.FlavorGroupsWorkloadSoftware.String()
					} else {
						addToNonSoftwareGroup = true
					}
					if !addToNonSoftwareGroup {
						flavorgroup, err := fcon.createFGIfNotExists(softwareFgName)
						if err != nil || flavorgroup.ID == uuid.Nil {
							defaultLog.Errorf("controllers/flavor_controller:addFlavorToFlavorgroup() Error getting %v flavorgroup", softwareFgName)
							if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
								defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
									"Error cleaning up already existing flavors on flavor creation failure")
							}
							return nil, err
						}
						flavorgroupsForQueue = append(flavorgroupsForQueue, *flavorgroup)
						flavorgroups = []hvs.FlavorGroup{*flavorgroup}
					} else {
						flavorgroupsForQueue = append(flavorgroupsForQueue, fgs...)
						flavorgroups = fgs
					}
					fetchHostData = true

				} else if flavorPart == fc.FlavorPartPlatform || flavorPart == fc.FlavorPartOs {
					flavorgroups = fgs
					flavorgroupsForQueue = append(flavorgroupsForQueue, flavorgroups...)
				}
			} else {
				defaultLog.Error("controllers/flavor_controller: addFlavorToFlavorgroup(): Unable to create flavors")
				if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
					defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
						"Error cleaning up already existing flavors on flavor creation failure")
				}
				return nil, errors.New("Unable to create flavors")
			}
			for _, flavorgroup := range flavorgroups {
				if _, ok := flavorgroupFlavorMap[flavorgroup.ID]; ok {
					flavorgroupFlavorMap[flavorgroup.ID] = append(flavorgroupFlavorMap[flavorgroup.ID], signedFlavorCreated.Flavor.Meta.ID)
				} else {
					flavorgroupFlavorMap[flavorgroup.ID] = []uuid.UUID{signedFlavorCreated.Flavor.Meta.ID}
				}
			}
		}
	}

	// for each flavorgroup, we have to associate it with flavors
	for fgId, fIds := range flavorgroupFlavorMap {
		_, err := fcon.FGStore.AddFlavors(fgId, fIds)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding flavors to flavorgroup %s", fgId.String())
			if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
				defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
					"Error cleaning up already existing flavors on flavor creation failure")
			}
		}
	}
	// get all the hosts that belong to the same flavor group and add them to flavor-verify queue
	err := fcon.addFlavorgroupHostsToFlavorVerifyQueue(flavorgroupsForQueue, fgHostIds, fetchHostData)
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding hosts to flavor-verify queue")
		if cleanUpErr := fcon.createCleanUp(flavorgroupFlavorMap); cleanUpErr != nil {
			defaultLog.WithError(cleanUpErr).Errorf("controllers/flavor_controller: addFlavorToFlavorgroup() : " +
				"Error cleaning up already existing flavors on flavor creation failure")
		}
		return nil, err
	}
	return returnSignedFlavors, nil
}

func (fcon FlavorController) addFlavorgroupHostsToFlavorVerifyQueue(fgs []hvs.FlavorGroup, hostIds []uuid.UUID, forceUpdate bool) error {
	defaultLog.Trace("controllers/flavor_controller:addFlavorgroupHostsToFlavorVerifyQueue() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorgroupHostsToFlavorVerifyQueue() Leaving")
	fgHosts := make(map[uuid.UUID]bool)

	// for each flavorgroup, find the hosts that belong to the flavorgroup
	// and add it to the list of host ID's
	for _, fg := range fgs {
		defaultLog.Debugf("Adding hosts that belong to %s flavorgroup", fg.Name)
		if fg.Name == dm.FlavorGroupsHostUnique.String() && len(hostIds) >= 1 {
			for _, hId := range hostIds {
				if _, ok := fgHosts[hId]; !ok {
					fgHosts[hId] = true
				}
			}
		} else {
			hIds, err := fcon.FGStore.SearchHostsByFlavorGroup(fg.ID)
			if err != nil {
				defaultLog.Errorf("controllers/flavor_controller:addFlavorgroupHostsToFlavorVerifyQueue(): Failed to fetch hosts linked to FlavorGroup")
				return err
			}
			for _, hId := range hIds {
				// adding to the list only if not already added
				if _, ok := fgHosts[hId]; !ok {
					fgHosts[hId] = true
				}
			}
		}
	}

	var hostIdsForQueue []uuid.UUID
	for hId := range fgHosts {
		hostIdsForQueue = append(hostIdsForQueue, hId)
	}

	defaultLog.Debugf("Found %v hosts to be added to flavor-verify queue", len(hostIdsForQueue))
	// adding all the host linked to flavorgroup to flavor-verify queue
	if len(hostIdsForQueue) >= 1 {
		err := fcon.HTManager.VerifyHostsAsync(hostIdsForQueue, forceUpdate, false)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Host to Flavor Verify Queue addition failed")
			return err
		}
	}
	return nil
}

// TODO : Convert for ESXI.
// func (fcon FlavorController) retrieveFlavorCollection(platformFlavor *fType.PlatformFlavor, fgs []hvs.FlavorGroup, flavorParts []fc.FlavorPart) map[fc.FlavorPart][]hvs.SignedFlavorFC {
// 	defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Entering")
// 	defer defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Leaving")

// 	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavor)
// 	flavorSignKey := (*fcon.CertStore)[dm.CertTypesFlavorSigning.String()].Key

// 	if fgs == nil || platformFlavor == nil {
// 		defaultLog.Error("controllers/flavor_controller:retrieveFlavorCollection() Platform flavor and flavorgroup must be specified")
// 		return flavorFlavorPartMap
// 	}

// 	if len(flavorParts) == 0 {
// 		flavorParts = append(flavorParts, fc.FlavorPartSoftware)
// 	}

// 	for _, flavorPart := range flavorParts {
// 		unsignedFlavors, err := (*platformFlavor).GetFlavorPartRaw(flavorPart)
// 		if err != nil {
// 			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error building a flavor for flavor part %s", flavorPart)
// 			return flavorFlavorPartMap
// 		}

// 		signedFlavors, err := fu.PlatformFlavorUtil{}.GetSignedFlavorListFC(unsignedFlavors, flavorSignKey.(*rsa.PrivateKey))
// 		if err != nil {
// 			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error signing flavor %s", flavorPart)
// 			return flavorFlavorPartMap
// 		}

// 		for _, signedFlavor := range signedFlavors {
// 			if _, ok := flavorFlavorPartMap[flavorPart]; ok {
// 				flavorFlavorPartMap[flavorPart] = append(flavorFlavorPartMap[flavorPart], signedFlavor)
// 			} else {
// 				flavorFlavorPartMap[flavorPart] = []hvs.SignedFlavor{signedFlavor}
// 			}
// 		}
// 	}
// 	return flavorFlavorPartMap
// }

func (fcon FlavorController) retrieveFlavorCollectionFC(platformFlavor *fType.PlatformFlavor, fgs []hvs.FlavorGroup, flavorParts []fc.FlavorPart) map[fc.FlavorPart][]hvs.SignedFlavorFC {
	defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Leaving")

	defaultLog.Debugf("Mahesh unsigned retrieveFlavorCollectionFC  platformFlavor ", platformFlavor)

	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavorFC)
	flavorSignKey := (*fcon.CertStore)[dm.CertTypesFlavorSigning.String()].Key

	defaultLog.Debugf("Mahesh retrieveFlavorCollectionFC  flavorSignKey ", flavorSignKey)

	if fgs == nil || platformFlavor == nil {
		defaultLog.Error("controllers/flavor_controller:retrieveFlavorCollection() Platform flavor and flavorgroup must be specified")
		return flavorFlavorPartMap
	}

	if len(flavorParts) == 0 {
		flavorParts = append(flavorParts, fc.FlavorPartSoftware)
	}

	defaultLog.Debugf("Mahesh retrieveFlavorCollectionFC  flavorParts ", flavorParts)

	for _, flavorPart := range flavorParts {

		defaultLog.Debugf("Mahesh retrieveFlavorCollectionFC  flavorPart ", flavorPart)

		unsignedFlavors, err := (*platformFlavor).GetFlavorPartRawFC(flavorPart)
		defaultLog.Debugf("Mahesh unsigned flavors -> ", unsignedFlavors)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error building a flavor for flavor part %s", flavorPart)
			return flavorFlavorPartMap
		}

		signedFlavors, err := fu.PlatformFlavorUtil{}.GetSignedFlavorListFC(unsignedFlavors, flavorSignKey.(*rsa.PrivateKey))
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error signing flavor %s", flavorPart)
			return flavorFlavorPartMap
		}

		defaultLog.Debugf("Mahesh signed flavors -> ", signedFlavors)

		for _, signedFlavor := range signedFlavors {
			if _, ok := flavorFlavorPartMap[flavorPart]; ok {
				flavorFlavorPartMap[flavorPart] = append(flavorFlavorPartMap[flavorPart], signedFlavor)
			} else {
				flavorFlavorPartMap[flavorPart] = []hvs.SignedFlavorFC{signedFlavor}
			}
		}
	}
	defaultLog.Debugf("Mahesh signed flavor MAP-> ", flavorFlavorPartMap)
	return flavorFlavorPartMap
}

func (fcon *FlavorController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query flavors")

	if err := utils.ValidateQueryParams(r.URL.Query(), flavorSearchParams); err != nil {
		secLog.Errorf("controllers/flavor_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	ids := r.URL.Query()["id"]
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	flavorgroupId := r.URL.Query().Get("flavorgroupId")
	flavorParts := r.URL.Query()["flavorParts"]

	filterCriteria, err := validateFlavorFilterCriteria(key, value, flavorgroupId, ids, flavorParts)
	if err != nil {
		secLog.Errorf("controllers/flavor_controller:Search()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	signedFlavors, err := fcon.FStore.Search(&dm.FlavorVerificationFC{
		FlavorFC: *filterCriteria,
	})
	if err != nil {
		secLog.WithError(err).Error("controllers/flavor_controller:Search() Flavor get all failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Unable to search Flavors")
	}

	secLog.Infof("%s: Return flavor query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hvs.SignedFlavorCollection{SignedFlavors: signedFlavors}, http.StatusOK, nil
}

func (fcon *FlavorController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Delete() Leaving")

	flavorId := uuid.MustParse(mux.Vars(r)["id"])
	flavor, err := fcon.FStore.Retrieve(flavorId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", flavorId).Info(
				"controllers/flavor_controller:Delete()  Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", flavorId).Info(
				"controllers/flavor_controller:Delete() Failed to delete Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
		}
	}

	hostIdsForQueue, err := getHostsAssociatedWithFlavor(fcon.HStore, fcon.FGStore, flavor)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Delete() Failed to retrieve hosts " +
			"associated with flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve hosts " +
			"associated with flavor for trust re-verification"}
	}

	if err := fcon.FStore.Delete(flavorId); err != nil {
		defaultLog.WithError(err).WithField("id", flavorId).Info(
			"controllers/flavor_controller:Delete() failed to delete Flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
	}

	defaultLog.Debugf("Found %v hosts to be added to flavor-verify queue", len(hostIdsForQueue))
	// adding all the host linked to flavor to flavor-verify queue
	if len(hostIdsForQueue) >= 1 {
		err := fcon.HTManager.VerifyHostsAsync(hostIdsForQueue, false, false)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:Delete() Host to Flavor Verify Queue addition failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to re-verify hosts " +
				"associated with deleted Flavor"}
		}
	}
	return nil, http.StatusNoContent, nil
}

func getHostsAssociatedWithFlavor(hStore domain.HostStore, fgStore domain.FlavorGroupStore, flavor *hvs.SignedFlavor) ([]uuid.UUID, error) {
	defaultLog.Trace("controllers/flavor_controller:getHostsAssociatedWithFlavor() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getHostsAssociatedWithFlavor() Leaving")

	id := flavor.Flavor.Meta.ID
	flavorGroups, err := fgStore.Search(&dm.FlavorGroupFilterCriteria{FlavorId: &id})
	if err != nil {
		return nil, errors.Wrapf(err, "controllers/flavor_controller:getHostsAssociatedWithFlavor() Failed to retrieve flavorgroups "+
			"associated with flavor %v for trust re-verification", id)
	}

	var hostIdsForQueue []uuid.UUID
	for _, flavorGroup := range flavorGroups {
		//Host unique flavors are associated with only host_unique flavorgroup and associated with only one host uniquely
		if flavorGroup.Name == dm.FlavorGroupsHostUnique.String() {
			hosts, err := hStore.Search(&dm.HostFilterCriteria{
				HostHardwareId: *flavor.Flavor.Meta.Description.HardwareUUID,
			})
			if err != nil {
				return nil, errors.Wrapf(err, "controllers/flavor_controller:getHostsAssociatedWithFlavor() Failed to retrieve hosts "+
					"associated with flavor %v for trust re-verification", id)
			}
			if len(hosts) > 0 {
				hostIdsForQueue = append(hostIdsForQueue, hosts[0].Id)
				break
			}
		}
		hostIds, err := fgStore.SearchHostsByFlavorGroup(flavorGroup.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "controllers/flavor_controller:getHostsAssociatedWithFlavor() Failed to retrieve hosts "+
				"associated with flavorgroup %v for trust re-verification", flavorGroup.ID)
		}
		hostIdsForQueue = append(hostIdsForQueue, hostIds...)
	}
	return hostIdsForQueue, nil
}

func (fcon *FlavorController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	flavor, err := fcon.FStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() failed to retrieve Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor with the given ID"}
		}
	}
	return flavor, http.StatusOK, nil
}

func validateFlavorFilterCriteria(key, value, flavorgroupId string, ids, flavorParts []string) (*dm.FlavorFilterCriteria, error) {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Leaving")

	filterCriteria := dm.FlavorFilterCriteria{}
	var err error
	if len(ids) > 0 {
		var fIds []uuid.UUID
		for _, fId := range ids {
			parsedId, err := uuid.Parse(fId)
			if err != nil {
				return nil, errors.New("Invalid UUID format of the flavor identifier")
			}
			fIds = append(fIds, parsedId)
		}
		filterCriteria.Ids = fIds
	}
	if key != "" && value != "" {
		if err = validation.ValidateStrings([]string{key, value}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for filter Key and Value must be specified")
		}
		filterCriteria.Key = key
		filterCriteria.Value = value
	}
	if flavorgroupId != "" {
		filterCriteria.FlavorgroupID, err = uuid.Parse(flavorgroupId)
		if err != nil {
			return nil, errors.New("Invalid UUID format of flavorgroup identifier")
		}
	}
	if len(flavorParts) > 0 {
		filterCriteria.FlavorParts, err = parseFlavorParts(flavorParts)
		if err != nil {
			return nil, errors.Wrap(err, "Valid contents of filter flavor_parts must be given")
		}
	}

	return &filterCriteria, nil
}

func validateFlavorCreateRequest(criteria dm.FlavorCreateRequest) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Leaving")

	if criteria.ConnectionString == "" && len(criteria.FlavorCollection.Flavors) == 0 && len(criteria.SignedFlavorCollection.SignedFlavors) == 0 {
		secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Valid host connection string or flavor content must be given")
		return errors.New("Valid host connection string or flavor content must be given")
	}
	if criteria.ConnectionString != "" {
		err := utils.ValidateConnectionString(criteria.ConnectionString)
		if err != nil {
			secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Invalid host connection string")
			return errors.New("Invalid host connection string")
		}
	}
	if len(criteria.FlavorgroupNames) != 0 {
		for _, flavorgroup := range criteria.FlavorgroupNames {
			if flavorgroup == "" {
				return errors.New("Valid Flavorgroup Names must be specified, empty name is not allowed")
			}
		}
		err := validation.ValidateStrings(criteria.FlavorgroupNames)
		if err != nil {
			return errors.New("Invalid flavorgroup name given as a flavor create criteria")
		}
	}
	if len(criteria.FlavorParts) > 0 {
		var flavorParts []string
		var err error
		for _, fp := range criteria.FlavorParts {
			flavorParts = append(flavorParts, fp.String())
		}
		criteria.FlavorParts, err = parseFlavorParts(flavorParts)
		if err != nil {
			return errors.New("Valid flavor parts must be given as a flavor create criteria")
		}
	}

	return nil
}

func validateFlavorMetaContent(meta *fm.Meta) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorMetaContent() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorMetaContent() Leaving")
	if meta == nil || reflect.DeepEqual(meta.Description, fm.Description{}) || meta.Description.Label == "" {
		return errors.New("Invalid flavor meta content : flavor label missing")
	}
	var fp fc.FlavorPart
	if err := (&fp).Parse(meta.Description.FlavorPart); err != nil {
		return errors.New("Flavor Part must be ASSET_TAG, SOFTWARE, HOST_UNIQUE, PLATFORM or OS")
	}
	return nil
}

func parseFlavorParts(flavorParts []string) ([]fc.FlavorPart, error) {
	defaultLog.Trace("controllers/flavor_controller:parseFlavorParts() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:parseFlavorParts() Leaving")
	// validate if the given flavor parts are valid and convert it to FlavorPart type
	var validFlavorParts []fc.FlavorPart
	for _, flavorPart := range flavorParts {
		var fp fc.FlavorPart
		if err := (&fp).Parse(flavorPart); err != nil {
			return nil, errors.New("Valid FlavorPart as a filter must be specified")
		}
		validFlavorParts = append(validFlavorParts, fp)
	}
	return validFlavorParts, nil
}

func (fcon *FlavorController) createFGIfNotExists(fgName string) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("controllers/flavor_controller:createFGIfNotExists() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createFGIfNotExists() Leaving")

	if fgName == "" {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Flavorgroup name cannot be nil")
		return nil, errors.New("Flavorgroup name cannot be nil")
	}

	flavorgroups, err := fcon.FGStore.Search(&dm.FlavorGroupFilterCriteria{
		NameEqualTo: fgName,
	})
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Error searching for flavorgroup with name %s", fgName)
		return nil, errors.Wrapf(err, "Error searching for flavorgroup with name %s", fgName)
	}

	if len(flavorgroups) > 0 && flavorgroups[0].ID != uuid.Nil {
		return &flavorgroups[0], nil
	}
	// if flavorgroup of the given name doesn't exist, create a new one
	var fg hvs.FlavorGroup
	var policies []hvs.FlavorMatchPolicy
	if fgName == dm.FlavorGroupsWorkloadSoftware.String() || fgName == dm.FlavorGroupsPlatformSoftware.String() {
		policies = append(policies, hvs.NewFlavorMatchPolicy(fc.FlavorPartSoftware, hvs.NewMatchPolicy(hvs.MatchTypeAnyOf, hvs.FlavorRequired)))
		fg = hvs.FlavorGroup{
			Name:          fgName,
			MatchPolicies: policies,
		}
	} else if fgName == dm.FlavorGroupsHostUnique.String() {
		fg = hvs.FlavorGroup{
			Name: fgName,
		}
	} else {
		fg = utils.CreateFlavorGroupByName(fgName)
	}

	flavorgroup, err := fcon.FGStore.Create(&fg)
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Flavor creation failed while creating flavorgroup"+
			"with name %s", fgName)
		return nil, errors.Wrap(err, "Unable to create flavorgroup")
	}
	return flavorgroup, nil
}

func (fcon *FlavorController) createCleanUp(fgFlavorMap map[uuid.UUID][]uuid.UUID) error {
	defaultLog.Trace("controllers/flavor_controller:createCleanUp() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createCleanUp() Leaving")
	if len(fgFlavorMap) <= 0 {
		return nil
	}
	defaultLog.Info("Error occurred while creating flavors. So, cleaning up already created flavors....")
	// deleting all the flavor created
	for _, fIds := range fgFlavorMap {
		for _, fId := range fIds {
			if err := fcon.FStore.Delete(fId); err != nil {
				defaultLog.Info("Failed to delete flavor and clean up when create flavors errored out")
				return errors.New("Failed to delete Flavor and clean up when create flavors errored out")
			}
		}
	}
	return nil
}

func checkValidFlavorPermission(privileges []ct.PermissionInfo, requiredPermission []string) bool {
	reqPermissions := ct.PermissionInfo{Service: consts.ServiceName, Rules: requiredPermission}
	_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
		true)
	if !foundMatchingPermission {
		secLog.Errorf("router/handlers:permissionsHandler() %s Insufficient privileges to access /v2/hvs/flavors", commLogMsg.UnauthorizedAccess)
		return false
	}
	return true
}
