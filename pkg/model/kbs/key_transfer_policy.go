/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

// KeyTransferPolicyAttributes - used in key transfer policy create request and response.
type KeyTransferPolicyAttributes struct {
	// swagger:strfmt uuid
	ID                                     uuid.UUID `json:"id,omitempty"`
	CreatedAt                              time.Time `json:"created_at,omitempty"`
	SGXEnclaveIssuerAnyof                  []string  `json:"sgx_enclave_issuer_anyof"`
	SGXEnclaveIssuerProductIDAnyof         []int16   `json:"sgx_enclave_issuer_product_id_anyof"`
	SGXEnclaveIssuerExtendedProductIDAnyof []string  `json:"sgx_enclave_issuer_extended_product_id_anyof,omitempty"`
	SGXEnclaveMeasurementAnyof             []string  `json:"sgx_enclave_measurement_anyof,omitempty"`
	SGXConfigIDSVN                         int16     `json:"sgx_config_id_svn"`
	SGXEnclaveSVNMinimum                   int16     `json:"sgx_enclave_svn_minimum,omitempty"`
	SGXConfigIDAnyof                       []string  `json:"sgx_config_id_anyof,omitempty"`
	TLSClientCertificateIssuerCNAnyof      []string  `json:"tls_client_certificate_issuer_cn_anyof,omitempty"`
	TLSClientCertificateSANAnyof           []string  `json:"client_permissions_anyof,omitempty"`
	TLSClientCertificateSANAllof           []string  `json:"client_permissions_allof,omitempty"`
	AttestationTypeAnyof                   []string  `json:"attestation_type_anyof,omitempty"`
	SGXEnforceTCBUptoDate                  bool      `json:"sgx_enforce_tcb_up_to_date,omitempty"`
}
