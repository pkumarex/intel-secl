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
type HardwareFeature struct {
	Supported bool `json:"supported,string"`
	Enabled   bool `json:"enabled,string"`
}

type CBNT struct {
	HardwareFeature
	Meta struct {
		Profile string `json:"profile"`
		MSR     string `json:"msr"`
	} `json:"meta"`
}

type TPM struct {
	HardwareFeature
	Meta struct {
		TPMVersion string   `json:"tpm_version"`
		PCRBanks   []string `json:"pcr_banks"`
	} `json:"meta"`
}

type UEFI struct {
	HardwareFeature
	Meta struct {
		SecureBootEnabled bool `json:"secure_boot_enabled"`
	} `json:"meta"`
}

// Feature encapsulates the presence of various Platform security features on the Host hardware
type Feature struct {
	AES_NI *AES_NI         `json:"AES_NI,omitempty"`
	TXT    HardwareFeature `json:"TXT"`
	TPM    TPM             `json:"TPM"`
	CBNT   CBNT            `json:"CBNT"`
	UEFI   UEFI            `json:"UEFI"`
	PFR    HardwareFeature `json:"PFR"`
	BMC    HardwareFeature `json:"BMC"`
}
