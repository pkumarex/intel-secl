/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"github.com/intel-secl/intel-secl/v3/pkg/cms/config"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateCmsAuthToken(t *testing.T) {
	log.Trace("tasks/authtoken_test:TestCreateCmsAuthToken() Entering")
	defer log.Trace("tasks/authtoken_test:TestCreateCmsAuthToken() Leaving")

	assertions := assert.New(t)
	CreateSerialNumberFileAndJWTDir()
	c := config.Configuration{}

	at := CmsAuthToken{
		ConsoleWriter: os.Stdout,
		AasTlsCn:      c.AasTlsCn,
		AasJwtCn:      c.AasJwtCn,
		AasTlsSan:     c.AasTlsSan,
		TokenDuration: c.TokenDurationMins,
	}

	err := createCmsAuthToken(at)
	assertions.NoError(err)
}

func TestAuthTokenRun(t *testing.T) {
	log.Trace("tasks/authtoken_test:TestAuthTokenRun() Entering")
	defer log.Trace("tasks/authtoken_test:TestAuthTokenRun() Leaving")

	assertions := assert.New(t)
	CreateSerialNumberFileAndJWTDir()
	c := config.Configuration{}

	ca := CmsAuthToken{
		ConsoleWriter: os.Stdout,
		AasTlsCn:      c.AasTlsCn,
		AasJwtCn:      c.AasJwtCn,
		AasTlsSan:     c.AasTlsSan,
		TokenDuration: c.TokenDurationMins,
	}

	err := ca.Run()
	assertions.NoError(err)
}
