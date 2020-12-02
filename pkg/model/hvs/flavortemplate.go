/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/google/uuid"
)

type Meta struct {
	FlavorPart  string `json:"flavor_part,omitempty"`
	Source      string `json:"source,omitempty"`
	Label       string `json:"label,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	BiosName    string `json:"bios_name,omitempty"`
	BiosVersion string `json:"bios_version,omitempty"`
	OsName      string `json:"os_name,omitempty"`
	OsVersion   string `json:"os_version,omitempty"`
	VmmName     string `json:"vmm_name,omitempty"`
	VmmVersion  string `json:"vmm_version,omitempty"`
	TpmVersion  string `json:"tpm_version,omitempty"`
	// swagger: strfmt uuid
	HardwareUUID *uuid.UUID `json:"hardware_uuid,omitempty"`
	Comment      string     `json:"comment,omitempty"`

	TbootInstalled bool `json:"tboot_installed,omitempty"`
	CBNTEnabled    bool `json:"cbnt_enabled,omitempty"`
	UEFIEnabled    bool `json:"uefi_enabled,omitempty"`

	DigestAlgorithm string `json:"digest_algorithm,omitempty"`
}

//PCR- Tp stpre PCR index with respective PCR bank.
type PCR struct {
	Index int    `json:"index"`
	Bank  string `json:"bank"`
}

//EventLogEquals - To store event log need be equal with specified PCR.
type EventLogEquals struct {
	ExculdingTags []string `json:"excluding_tags"`
}

type PcrRules []struct {
	Pcr              PCR             `json:"pcr"`
	PcrMatches       bool            `json:"pcr_matches"`
	EventlogEquals   *EventLogEquals `json:"eventlog_equals,omitempty"`
	EventlogIncludes *[]string       `json:"eventlog_includes"`
}

// swagger:parameters FlavorPart
type FlavorPart struct {
	Meta     *Meta    `json:"meta,omitempty"`
	PcrRules PcrRules `json:"pcr_rules"`
}

// swagger:parameters FlavorParts
type FlavorParts struct {
	Platform   *FlavorPart `json:"PLATFORM,omitempty"`
	OS         *FlavorPart `json:"OS,omitempty"`
	Software   *FlavorPart `json:"SOFTWARE,omitempty"`
	HostUnique *FlavorPart `json:"HOST_UNIQUE,omitempty"`
	AssetTag   *FlavorPart `json:"ASSET_TAG,omitempty"`
}

type FlavorTemplate struct {
	// swagger: strfmt uuid
	ID          uuid.UUID   `json:"id" gorm:"primary_key;type:uuid"`
	Label       string      `json:"label"`
	Condition   []string    `json:"condition" sql:"type:text[]"`
	FlavorParts FlavorParts `json:"flavor-parts,omitempty" sql:"type:JSONB"`
}
