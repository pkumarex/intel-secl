/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavorgen

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	hcType "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

type FlavorPartTypes string

//create the flavorpart json
func createFlavor(linuxPlatformFlavor types.LinuxPlatformFlavor) error {
	log.Println("flavor_create:createFlavor() Entering")
	defer log.Println("flavor_create:createFlavor() Leaving")

	var flavors []hvs.SignedFlavor

	flavorParts := [3]FlavorPartTypes{cf.FlavorPartPlatform, cf.FlavorPartOs, cf.FlavorPartHostUnique}

	flavorSignKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return errors.Wrap(err, "flavor_create:createFlavor() Couldn't generate RSA key, failed to create flavorsinging key")
	}

	for _, flavorPart := range flavorParts {

		unSignedFlavors, err := linuxPlatformFlavor.GetFlavorPartRaw(flavorPart)
		if err != nil {
			return errors.Wrapf(err, "flavor_create:createFlavor() Unable to create flavor part %s", flavorPart)
		}
		signedFlavors, err := GetSignedFlavorList(unSignedFlavors, flavorSignKey)
		if err != nil {
			return errors.Wrapf(err, "flavor_create:createFlavor() Failed to create signed flavor %s", flavorPart)
		}

		flavors = append(flavors, signedFlavors...)
	}

	signedFlavorCollection := model.SignedFlavorCollection{
		SignedFlavors: flavors,
	}

	flavorJSON, err := json.Marshal(signedFlavorCollection)
	if err != nil {
		return errors.Wrapf(err, "flavor_create:createFlavor() Couldn't marshal signedflavorCollection")
	}
	flavorPartJSON := string(flavorJSON)
	fmt.Println(flavorPartJSON)
	return nil
}

// GetSignedFlavor is used to sign the flavor
func GetSignedFlavor(unsignedFlavor *model.Flavor, privateKey *rsa.PrivateKey) (*model.SignedFlavor, error) {
	log.Println("utils:GetSignedFlavor() Entering")
	defer log.Println("utils:GetSignedFlavor() Leaving")

	if unsignedFlavor == nil {
		return nil, errors.New("utils:GetSignedFlavor: Flavor content missing")
	}

	signedFlavor, err := NewSignedFlavor(unsignedFlavor, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "utils:GetSignedFlavor: Error while creating signed flavor")
	}

	return signedFlavor, nil
}

// GetSignedFlavorList performs a bulk signing of a list of flavor strings and returns a list of SignedFlavors
func GetSignedFlavorList(flavors []model.Flavor, flavorSigningPrivateKey *rsa.PrivateKey) ([]model.SignedFlavor, error) {
	log.Println("utils:GetSignedFlavorList() Entering")
	defer log.Println("utils:GetSignedFlavorList() Leaving")

	var signedFlavors []model.SignedFlavor

	if flavors != nil {
		// Loop through and sign each flavor
		for _, unsignedFlavor := range flavors {
			var sf *model.SignedFlavor

			sf, err := GetSignedFlavor(&unsignedFlavor, flavorSigningPrivateKey)
			if err != nil {
				return nil, errors.Errorf("utils:GetSignedFlavorList() Error signing flavor collection: %s", err.Error())
			}

			signedFlavors = append(signedFlavors, *sf)
		}
	} else {
		return nil, errors.Errorf("utils:GetSignedFlavorList() Empty flavors list provided")
	}
	return signedFlavors, nil
}

// NewSignedFlavor Provided an existing flavor and a privatekey, create a SignedFlavor
func NewSignedFlavor(flavor *model.Flavor, privateKey *rsa.PrivateKey) (*model.SignedFlavor, error) {
	log.Println("utils:NewSignedFlavor() Entering")
	defer log.Println("utils:NewSignedFlavor() Leaving")

	if flavor == nil {
		return nil, errors.New("utils:NewSignedFlavor() The Flavor must be provided and cannot be nil")
	}

	if privateKey == nil || privateKey.Validate() != nil {
		return nil, errors.New("utils:NewSignedFlavor() Valid private key must be provided and cannot be nil")
	}

	flavorDigest, err := getFlavorDigest(flavor)
	if err != nil {
		return nil, errors.Wrap(err, "utils:NewSignedFlavor() An error occurred while getting flavor digest")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, flavorDigest)
	if err != nil {
		return nil, errors.Wrap(err, "utils:NewSignedFlavor() An error occurred while signing the flavor")
	}

	return &model.SignedFlavor{
		Flavor:    *flavor,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

//getFlavorDigest to get digest for flavor
func getFlavorDigest(flavor *model.Flavor) ([]byte, error) {
	log.Println("flavor_signing:getFlavorDigest() Entering")
	defer log.Println("flavor_signing:getFlavorDigest() Leaving")
	// Account for a differences in properties set at runtime
	tempFlavor := *flavor
	tempFlavor.Meta.ID = uuid.Nil

	flavorJSON, err := json.Marshal(tempFlavor)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_signing:getFlavorDigest() An error occurred attempting to convert the flavor to json")
	}

	if flavorJSON == nil || len(flavorJSON) == 0 {
		return nil, errors.New("flavor_signing:getFlavorDigest() The flavor json was not provided")
	}

	hashEntity := sha512.New384()
	_, err = hashEntity.Write(flavorJSON)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_signing:getFlavorDigest() Error creating flavor digest")
	}

	return hashEntity.Sum(nil), nil
}
