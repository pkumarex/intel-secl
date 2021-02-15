/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/google/uuid"

type HostFilterCriteria struct {
	Id             uuid.UUID
	HostHardwareId uuid.UUID
	NameEqualTo    string
	NameContains   string
	Key            string
	Value          string
	IdList         []uuid.UUID
	Trusted        *bool
}
