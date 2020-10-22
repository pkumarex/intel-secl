/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"time"
	"github.com/Waterdrips/jwt-go"
	"github.com/google/uuid"
)

// HostResponse Response on getting hosts from kubernetes
type HostResponse struct {
	Items []struct {
		Spec struct {
			Taints []struct {
				Key       string    `json:"key"`
				Effect    string    `json:"effect"`
				TimeAdded time.Time `json:"timeAdded,omitempty"`
			} `json:"taints"`
		} `json:"spec"`
		Status struct {
			Addresses []struct {
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"addresses"`
			NodeInfo struct {
				SystemID string `json:"systemUUID"`
			} `json:"nodeInfo"`
		} `json:"status"`
	} `json:"items"`
}

// CRD Data to update in kubernetes
type CRD struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

// Metadata details for CRD data
type Metadata struct {
	CreationTimestamp time.Time `json:"creationTimestamp"`
	Generation        int       `json:"generation"`
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	ResourceVersion   string    `json:"resourceVersion"`
	SelfLink          string    `json:"selfLink"`
	UID               uuid.UUID `json:"uid"`
}

// Host holds details of registered hosts pushed to K8s endpoint
type Host struct {
	Updated           *time.Time        `json:"updatedTime,omitempty"`
	AssetTags         map[string]string `json:"assetTags,omitempty"`
	HardwareFeatures  map[string]string `json:"hardwareFeatures,omitempty"`
	Trust             map[string]string `json:"trust,omitempty"`
	HostName          string            `json:"hostName"`
	SignedTrustReport string            `json:"signedTrustReport,omitempty"`
	Trusted           *bool             `json:"trusted,omitempty"`
	ValidTo           time.Time         `json:"validTo,omitempty"`
	HostID            string            `json:"host-id,omitempty"`
	SgxSupported      string            `json:"sgx-supported,omitempty"`
	SgxEnabled        string            `json:"sgx-enabled,omitempty"`
	FlcEnabled        string            `json:"flc-enabled,omitempty"`
	EpcSize           string            `json:"epc-size,omitempty"`
	TcbUpToDate       string            `json:"tcbUpToDate,omitempty"`
	jwt.StandardClaims
}

// Spec details for CRD Data
type Spec struct {
	HostList []Host `json:"hostList"`
}
