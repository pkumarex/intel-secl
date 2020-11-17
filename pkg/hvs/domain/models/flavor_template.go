/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/google/uuid"

//Meta - To store all meta data about host.
type Meta struct {
	BiosName       string `json:"bios_name,omitempty"`
	BiosVersion    string `json:"bios_version,omitempty"`
	TpmVersion     string `json:"tpm_version,omitempty"`
	CBNTEnabled    bool   `json:"cbnt_enabled,omitempty"`
	TbootInstalled bool   `json:"tboot_installed,omitempty"`
}

//PCR- Tp stpre PCR index with respective PCR bank.
type PCR struct {
	Index int    `json:"index"`
	Bank  string `json:"bank"`
}

//EventLogEquals - To store event log need be equal with specified PCR.
type EventLogEquals struct {
	PCR           PCR      `json:"pcr"`
	ExculdingTags []string `json:"excluding_tags,omitempty"`
}

//EventLogEquals - To store Event Log need be included with specified PCR.
type EventLogIncludes struct {
	PCR         PCR      `json:"pcr"`
	IncludeTags []string `json:"include_tags,omitempty"`
}

//Flavor - To store flavor with meta, event-log-equals and event-log-includes.
type Flavor struct {
	Meta             Meta               `json:"meta,omitempty"`
	PCRMatches       []PCR              `json:"pcr_matches,omitempty"`
	EventLogEquals   []EventLogEquals   `json:"eventlog_equals,omitempty"`
	EventLogIncludes []EventLogIncludes `json:"eventlog_includes,omitempty"`
}

//FlavorParts - To store possible flavor part requested.
type FlavorParts struct {
	Platform   Flavor `json:"PLATFORM,omitempty"`
	OS         Flavor `json:"OS,omitempty"`
	Software   Flavor `json:"SOFTWARE,omitempty"`
	HostUnique Flavor `json:"HOST_UNIQUE,omitempty"`
	AssetTag   Flavor `json:"ASSET_TAG,omitempty"`
}

type FlavorTemplateContent struct {
	FlavorGroupNames []string    `json:"flavorgroup_names,omitempty"`
	Label            string      `json:"label"`
	Condition        []string    `json:"condition" sql:"type:text[]"`
	FlavorParts      FlavorParts `json:"flavor-parts,omitempty" sql:"type:JSONB"`
}

//FlavorTemplate - To maintain all values keep together inorder to maintain flavor template.
type FlavorTemplate struct {
	ID               uuid.UUID   `json:"id" gorm:"primary_key;type:uuid"`
	FlavorgroupNames []string    `json:"flavorgroup_names,omitempty"`
	Label            string      `json:"label"`
	Condition        []string    `json:"condition" sql:"type:text[]"`
	FlavorParts      FlavorParts `json:"flavor-parts,omitempty" sql:"type:JSONB"`
}
