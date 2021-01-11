/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

type TpmQuoteRequest struct {
	Nonce    []byte   `json:"nonce"`
	Pcrs     []int    `json:"pcrs"`
	PcrBanks []string `json:"pcrbanks"`
}
