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

	assert := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
	defer os.Remove(temp.Name())
	c, _ := config.Load()

	_, certData, err := createRootCACert(&c.CACert)
	assert.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assert.NoError(err)
	assert.True(cert.IsCA)
}

func TestRootCASetupTaskRun(t *testing.T) {
	log.Trace("tasks/rootca_test:TestRootCASetupTaskRun() Entering")
	defer log.Trace("tasks/rootca_test:TestRootCASetupTaskRun() Leaving")

	assert := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
	defer os.Remove(temp.Name())
	c, _ := config.Load()

	ca := RootCa{
		ConsoleWriter:   os.Stdout,
		CACertConfigPtr: &c.CACert,
		CACertConfig:    c.CACert,
	}

	err := ca.Run()
	assert.NoError(err)
}
