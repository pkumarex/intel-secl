/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	log "github.com/sirupsen/logrus"
	"io"

	"os"

	"github.com/pkg/errors"
)

//CreateSigningKey Struct to create Encryption key
type CreateSigningKey struct {
	PrivateKeyLocation string
	PublicKeyLocation  string
	KeyAlgorithmLength int
}

// Validate CreateKey method is used to check if the keyPair exists on disk
func (signingKey CreateSigningKey) Validate() error {
	_, err := os.Stat(signingKey.PrivateKeyLocation)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_signing_keypair:Validate() Private key does not exist")
	}

	_, err = os.Stat(signingKey.PublicKeyLocation)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_signing_keypair:Validate() Public key does not exist")
	}
	return nil
}

//Run Runs the setup task
func (signingKey CreateSigningKey) Run() error {
	bitSize := signingKey.KeyAlgorithmLength
	privateKey, publicKey, err := crypt.GenerateKeyPair("rsa", bitSize)
	if err != nil {
		return errors.Wrap(err, "tasks/create_signing_keypair:Run() Error while generating a new RSA key pair")
	}

	pkcs8Der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return errors.Wrap(err, "tasks/create_signing_keypair:Run() Error marshalling private key")
	}

	err = crypt.SavePrivateKeyAsPKCS8(pkcs8Der, signingKey.PrivateKeyLocation)
	if err != nil {
		return errors.Wrapf(err, "tasks/create_signing_keypair:Run() Failed to save private key to file:%s", signingKey.PrivateKeyLocation)
	}

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return errors.Wrap(err, "tasks/create_signing_keypair:Run() Error while marshalling the public key")
	}
	var publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyBytes,
	}

	publicKeyFile, err := os.OpenFile(signingKey.PublicKeyLocation, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "tasks/create_signing_keypair:Run() Error while creating a new public key")
	}
	defer func() {
		derr := publicKeyFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	err = pem.Encode(publicKeyFile, publicKeyInPem)
	if err != nil {
		return errors.Wrap(err, "tasks/create_signing_keypair:Run() Error while encoding the public key")
	}
	err = os.Chmod(signingKey.PublicKeyLocation, 0640)
	if err != nil {
		return errors.Wrapf(err, "tasks/create_signing_keypair:Run() Error while changing file permission for file : %s", signingKey.PublicKeyLocation)
	}
	return nil
}

func (signingKey CreateSigningKey) PrintHelp(w io.Writer) {}

func (signingKey CreateSigningKey) SetName(n, e string) {}
