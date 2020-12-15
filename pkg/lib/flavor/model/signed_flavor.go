/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

/**
 *
 * @author mullas
 */

// SignedFlavor combines the Flavor along with the cryptographically signed hash that authenticates its source
type SignedFlavor struct {
	Flavor    Flavor `json:"flavor"`
	Signature string `json:"signature"`
}

// // SignedFlavorFC combines the Flavor along with the cryptographically signed hash that authenticates its source
// type SignedFlavorFC struct {
// 	Flavor    FlavorFC `json:"flavorFC"`
// 	Signature string   `json:"signature"`
// }

// NewSignedFlavor Provided an existing flavor and a privatekey, create a SignedFlavor
func NewSignedFlavor(flavor *Flavor, privateKey *rsa.PrivateKey) (*SignedFlavor, error) {

	if flavor == nil {
		return nil, errors.New("The Flavor must be provided and cannot be nil")
	}

	if privateKey == nil || privateKey.Validate() != nil {
		return nil, errors.New("Valid private key must be provided and cannot be nil")
	}

	flavorDigest, err := flavor.getFlavorDigest()
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred while creating the signed flavor")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, flavorDigest)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred while signing the flavor")
	}

	log.Debug("Flavor Digest: ", base64.StdEncoding.EncodeToString(flavorDigest))
	log.Debug("Flavor Signature: ", base64.StdEncoding.EncodeToString(signature))
	return &SignedFlavor{
		Flavor:    *flavor,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// // NewSignedFlavor Provided an existing flavor and a privatekey, create a SignedFlavor
// func NewSignedFlavorFC(flavor *FlavorFC, privateKey *rsa.PrivateKey) (*SignedFlavorFC, error) {

// 	if flavor == nil {
// 		return nil, errors.New("The Flavor must be provided and cannot be nil")
// 	}

// 	if privateKey == nil || privateKey.Validate() != nil {
// 		return nil, errors.New("Valid private key must be provided and cannot be nil")
// 	}

// 	flavorDigest, err := flavor.getFlavorDigest()
// 	if err != nil {
// 		return nil, errors.Wrap(err, "An error occurred while creating the signed flavor")
// 	}

// 	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, flavorDigest)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "An error occurred while signing the flavor")
// 	}

// 	log.Debug("Flavor Digest: ", base64.StdEncoding.EncodeToString(flavorDigest))
// 	log.Debug("Flavor Signature: ", base64.StdEncoding.EncodeToString(signature))
// 	return &SignedFlavorFC{
// 		Flavor:    *flavor,
// 		Signature: base64.StdEncoding.EncodeToString(signature),
// 	}, nil
// }

// Verify Provided the public key from the Flavor Signing Certificate,
// verify that the signed flavor's signature is valid.
func (signedFlavor *SignedFlavor) Verify(publicKey *rsa.PublicKey) error {

	if len(signedFlavor.Signature) == 0 {
		return errors.New("Could not verify the signed flavor: The signed flavor that does not have a signature")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signedFlavor.Signature)
	if err != nil {
		return errors.Wrap(err, "Could not verify the signed flavor: An error occurred attempting to decode the signed flavor's signature")
	}

	flavorDigest, err := signedFlavor.Flavor.getFlavorDigest()
	if err != nil {
		return errors.Wrap(err, "Could not verify the signed flavor: An error occurred collecting the flavor digest")
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, flavorDigest, signatureBytes)
	if err != nil {
		return errors.Wrap(err, "Could not verify the signed flavor: PKCS1 verification failed")
	}

	return nil
}
