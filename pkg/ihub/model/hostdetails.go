/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"github.com/google/uuid"
	"time"
)

//HostDetails contains common attributes for CRD data to update across consumers
type HostDetails struct {
	HostName          string
	HostIP            string
	HostID            uuid.UUID
	Trusted           bool
	AssetTags         map[string]string
	HardwareFeatures  map[string]string
	Trust             map[string]string
	SignedTrustReport string
	ValidTo           time.Time
	SgxSupported      bool
	SgxEnabled        bool
	FlcEnabled        bool
	EpcSize           string
	TcbUpToDate       bool
}
