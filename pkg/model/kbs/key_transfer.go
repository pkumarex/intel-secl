/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package kbs

type KeyTransferResponse struct {
	KeyInfo   KeyTransferAttributes `json:"data"`
	Operation string                `json:"operation"`
	Status    string                `json:"status"`
}
