/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

type FlavorTemplateContent struct {
	Label       string          `json:"label"`
	Condition   []string        `json:"condition" sql:"type:text[]"`
	FlavorParts hvs.FlavorParts `json:"flavor_parts,omitempty" sql:"type:JSONB"`
}
