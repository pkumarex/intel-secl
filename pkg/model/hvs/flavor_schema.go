/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

type EventLogCreteria struct {
	TypeID      int      `json:"type_id"`     //oneof-required
	TypeName    string   `json:"type_name"`   //oneof-required
	Tags        []string `json:"tags"`        //oneof-required
	Measurement string   `json:"measurement"` //required
}

type EventLogEqual struct {
	Events      []EventLogCreteria `json:"events"`
	ExcludeTags []string           `json:"exclude_tags"`
}

type PCRS struct {
	PCR              PCR                `json:"pcr"`         //required
	Measurement      string             `json:"measurement"` //required
	PCRMatches       bool               `json:"pcr_matches"`
	EventlogEqual    []EventLogEqual    `json:"eventlog_equals"`
	EventlogIncludes []EventLogCreteria `json:"eventlog_includes"`
}

type FlavorSchema struct {
	ID         string `json:"id"`
	FlavorPart string `json:"flavor_part"`
	Meta       Meta   `json:"meta"`
	PCRS       []PCRS `json:"pcrs"`
}
