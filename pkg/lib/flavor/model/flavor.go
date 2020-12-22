/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"crypto/sha512"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// Flavor is a standardized set of expectations that determines what platform
// measurements will be considered “trusted.”
type Flavor struct {
	// Meta section is mandatory for all Flavor types
	Meta Meta  `json:"meta"`
	Bios *Bios `json:"bios,omitempty"`
	// Hardware section is unique to Platform Flavor type
	Hardware *Hardware                   `json:"hardware,omitempty"`
	Pcrs     map[string]map[string]PcrEx `json:"pcrs,omitempty"`
	PcrLogs  []types.PCRS                `json:"pcr_logs,omitempty"`
	// External section is unique to AssetTag Flavor type
	External *External `json:"external,omitempty"`
	Software *Software `json:"software,omitempty"`
}

// NewFlavor returns a new instance of Flavor
func NewFlavor(meta *Meta, bios *Bios, hardware *Hardware, pcrs map[crypt.DigestAlgorithm]map[types.PcrIndex]PcrEx, pcrlogs []types.PCRS, external *External, software *Software) *Flavor {
	// Since maps are hard to marshal as JSON, let's try to convert the DigestAlgorithm and PcrIndex to strings
	pcrx := make(map[string]map[string]PcrEx)
	for dA, shaBank := range pcrs {
		pcrx[dA.String()] = make(map[string]PcrEx)
		for pI, pE := range shaBank {
			pcrx[dA.String()][pI.String()] = pE
		}
	}
	return &Flavor{
		Meta:     *meta,
		Bios:     bios,
		Hardware: hardware,
		Pcrs:     pcrx,
		PcrLogs:  pcrlogs,
		External: external,
		Software: software,
	}
}

// // NewFlavorFV returns a new instance of Flavor
// func NewFlavorFC(meta *Meta, bios *Bios, hardware *Hardware, Pcrs []types.PCRS, external *External, software *Software) *FlavorFC {

// 	return &FlavorFC{
// 		Meta:     *meta,
// 		Bios:     bios,
// 		Hardware: hardware,
// 		Pcrs:     Pcrs,
// 		External: external,
// 		Software: software,
// 	}
// }

// Utility function for retrieving the PcrEx value at 'bank', 'index'.  Returns
// an error if the pcr cannot be found.
func (flavor *Flavor) GetPcrValue(bank types.SHAAlgorithm, index types.PcrIndex) (*PcrEx, error) {

	if indexMap, ok := flavor.Pcrs[string(bank)]; ok {
		if pcrValue, ok := indexMap[index.String()]; ok {
			return &pcrValue, nil
		} else {
			return nil, errors.Errorf("The flavor does not contain a pcr values for bank '%s', index %d", bank, index)
		}
	} else {
		return nil, errors.Errorf("The flavor does not contain any pcr values for bank '%s'", bank)
	}
}

// GetFlavorDigest Calculates the SHA384 hash of the Flavor's json data for use when
// signing/verifying signed flavors.
func (flavor *Flavor) getFlavorDigest() ([]byte, error) {
	// account for a differences in properties set at runtime
	tempFlavor := *flavor
	tempFlavor.Meta.ID = uuid.Nil

	flavorJSON, err := json.Marshal(tempFlavor)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred attempting to convert the flavor to json")
	}

	if flavorJSON == nil || len(flavorJSON) == 0 {
		return nil, errors.New("The flavor json was not provided")
	}

	hashEntity := sha512.New384()
	hashEntity.Write(flavorJSON)

	return hashEntity.Sum(nil), nil
}

// func (flavor *FlavorFC) getFlavorDigest() ([]byte, error) {
// 	// account for a differences in properties set at runtime
// 	tempFlavor := *flavor
// 	tempFlavor.Meta.ID = uuid.Nil

// 	flavorJSON, err := json.Marshal(tempFlavor)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "An error occurred attempting to convert the flavor to json")
// 	}

// 	if flavorJSON == nil || len(flavorJSON) == 0 {
// 		return nil, errors.New("The flavor json was not provided")
// 	}

// 	hashEntity := sha512.New384()
// 	hashEntity.Write(flavorJSON)

// 	return hashEntity.Sum(nil), nil
// }
