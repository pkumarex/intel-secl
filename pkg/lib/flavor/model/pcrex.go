/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"reflect"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

/**
 *
 * @author mullas
 */

// PcrEx represents a state of an individual PCR along with the event measurement logs that trace the evolution of
// the PCR state from system boot
type PcrEx struct {
	Value string             `json:"value"`
	Event []hcTypes.EventLog `json:"event,omitempty"`
}

type EventLogCreteria struct {
	TypeID      string    `json:"type_id"`   //oneof-required
	TypeName    string    `json:"type_name"` //oneof-required
	Tags        *[]string `json:"tags,omitempty"`
	Measurement string    `json:"measurement"` //required
}

type PCR struct {
	Index int    `json:"index"`
	Bank  string `json:"bank"`
}

//NewFVPcrEx
type NewFVPcrEx struct {
	PCR              PCR                   `json:"pcr"`         //required
	Measurement      string                `json:"measurement"` //required
	PCRMatches       bool                  `json:"pcr_matches,omitempty"`
	EventlogEqual    NewFVEventlogEquals   `json:"eventlog_equals,omitempty"`
	EventlogIncludes []types.NewFVEventLog `json:"eventlog_includes,omitempty"`
}

//NewFVEventlogEquals holds the log data of Equals
type NewFVEventlogEquals struct {
	Events      []types.NewFVEventLog `json:"events,omitempty"`
	ExcludeTags []string              `json:"exclude_tags,omitempty"`
}

// NewPcrEx returns a initialized PcrEx instance
func NewPcrEx(value string, event []hcTypes.EventLog) *PcrEx {
	return &PcrEx{
		Value: value,
		Event: event,
	}
}

func (p NewFVPcrEx) EqualsWithoutValue(pcr NewFVPcrEx) bool {
	return reflect.DeepEqual(p.PCR.Index, pcr.PCR.Index) && reflect.DeepEqual(p.PCR.Bank, pcr.PCR.Bank)
}
