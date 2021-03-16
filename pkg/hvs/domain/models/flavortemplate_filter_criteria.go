/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/google/uuid"

type FlavorTemplateFilterCriteria struct {
	Id                 uuid.UUID
	Label              string
	ConditionContains  string
	FlavorPartContains string
	IncludeDeleted     bool
}
