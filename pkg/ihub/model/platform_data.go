/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"time"
)

//PlatformDataSGX platform holds data for SGX
type PlatformDataSGX []struct {
	HostID       string    `json:"host_id"`
	SgxSupported bool      `json:"sgx_supported"`
	SgxEnabled   bool      `json:"sgx_enabled"`
	FlcEnabled   bool      `json:"flc_enabled"`
	EpcSize      string    `json:"epc_size"`
	TcbUpToDate  bool      `json:"tcb_upToDate"`
	ValidTo      time.Time `json:"validTo"`
}
