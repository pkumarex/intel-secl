/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "github.com/google/uuid"

/**
 *
 * @author mullas
 */

// Description is a component of Flavor that holds some information on the Flavor
type Description struct {
	FlavorPart  string `json:"flavor_part,omitempty"`
	Source      string `json:"source,omitempty"`
	Label       string `json:"label,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	BiosName    string `json:"bios_name,omitempty"`
	BiosVersion string `json:"bios_version,omitempty"`
	OsName      string `json:"os_name,omitempty"`
	OsVersion   string `json:"os_version,omitempty"`
	VmmName     string `json:"vmm_name,omitempty"`
	VmmVersion  string `json:"vmm_version,omitempty"`
	TpmVersion  string `json:"tpm_version,omitempty"`
	// swagger:strfmt uuid
	HardwareUUID    *uuid.UUID `json:"hardware_uuid,omitempty"`
	Comment         string     `json:"comment,omitempty"`
	TbootInstalled  *bool      `json:"tboot_installed,string,omitempty"`
	DigestAlgorithm string     `json:"digest_algorithm,omitempty"`
}
