/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// AES_NI
type AES_NI struct {
	Enabled bool `json:"enabled,omitempty"`
}

// TPM
type TPM struct {
	HardwareFeature
	Version  string   `json:"version,omitempty"`
	PcrBanks []string `json:"pcr_banks,omitempty"`
}

// CBNT
type CBNT struct {
	HardwareFeature
	Meta struct {
		Profile string `json:"profile"`
		MSR     string `json:"msr"`
	} `json:"meta"`
}

type HardwareFeature struct {
	Enabled bool `json:"enabled,omitempty"`
}

// UEFI
type UEFI struct {
	HardwareFeature
	Meta struct {
		SecureBootEnabled bool `json:"secure_boot_enabled,omitempty"`
	} `json:"meta"`
}

// Feature encapsulates the presence of various Platform security features on the Host hardware
type Feature struct {
	AES_NI *AES_NI          `json:"AES_NI,omitempty"`
	TXT    *HardwareFeature `json:"TXT,omitempty"`
	TPM    *TPM             `json:"TPM,omitempty"`
	CBNT   *CBNT            `json:"CBNT,omitempty"`
	UEFI   *UEFI            `json:"SUEFI,omitempty"`
}
