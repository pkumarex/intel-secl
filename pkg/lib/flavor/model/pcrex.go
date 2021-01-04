/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"

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

// NewPcrEx returns a initialized PcrEx instance
func NewPcrEx(value string, event []hcTypes.EventLog) *PcrEx {
	return &PcrEx{
		Value: value,
		Event: event,
	}
}
