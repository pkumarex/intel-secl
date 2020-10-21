/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/google/uuid"

//KeyFilterCriteria stores the parameters for filtering the keys
type KeyFilterCriteria struct {
	Algorithm        string
	KeyLength        int
	CurveType        string
	TransferPolicyId uuid.UUID
}
