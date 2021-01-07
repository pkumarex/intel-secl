/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/config"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRootCACertCreation(t *testing.T) {
	log.Trace("tasks/rootca_test:TestRootCACertCreation() Entering")
	defer log.Trace("tasks/rootca_test:TestRootCACertCreation() Leaving")

	assertions := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

	temp, err := ioutil.TempFile("", "config.yml")
	if err != nil {
		log.WithError(err).Error("tasks/rootca_test:TestRootCACertCreation() Error creating temp file")
	}
	_, err = temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
	if err != nil {
		log.WithError(err).Error("tasks/rootca_test:TestRootCACertCreation() Error writing to file")
	}
	defer func() {
		derr := os.Remove(temp.Name())
		if derr != nil {
			log.WithError(derr).Error("Error removing temporary file")
		}
	}()
	c, err := config.Load()
	if err != nil {
		log.WithError(err).Error("tasks/rootca_test:TestRootCACertCreation() Error loading config")
	}

	_, certData, err := createRootCACert(&c.CACert)
	assertions.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assertions.NoError(err)
	assertions.True(cert.IsCA)
}

func TestRootCASetupTaskRun(t *testing.T) {
	log.Trace("tasks/rootca_test:TestRootCASetupTaskRun() Entering")
	defer log.Trace("tasks/rootca_test:TestRootCASetupTaskRun() Leaving")

	assertions := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

	temp, err := ioutil.TempFile("", "config.yml")
	if err != nil {
		log.WithError(err).Error("tasks/rootca_test:TestRootCASetupTaskRun() Error creating temp file")
	}

	_, err = temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
	if err != nil {
		log.WithError(err).Error("tasks/rootca_test:TestRootCASetupTaskRun() Error writing to file")
	}
	defer func() {
		derr := os.Remove(temp.Name())
		if derr != nil {
			log.WithError(derr).Error("Error removing temporary file")
		}
	}()
	c, err := config.Load()
	if err != nil {
		log.WithError(err).Error("tasks/rootca_test:TestRootCASetupTaskRun() Error loading config")
	}

	ca := RootCa{
		ConsoleWriter:   os.Stdout,
		CACertConfigPtr: &c.CACert,
		CACertConfig:    c.CACert,
	}

	err = ca.Run()
	assertions.NoError(err)
}
