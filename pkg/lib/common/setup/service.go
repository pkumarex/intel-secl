/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"fmt"
	"io"

	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
)

type ServiceSetup struct {
	commConfig.ServiceConfig
	AASApiUrl        string
	CMSBaseURL       string
	CmsTlsCertDigest string

	SvcConfigPtr        *commConfig.ServiceConfig
	AASApiUrlPtr        *string
	CMSBaseURLPtr       *string
	CmsTlsCertDigestPtr *string

	ConsoleWriter io.Writer

	envPrefix   string
	commandName string
}

const svcEnvHelpPrompt = "Following service specific environment variables are required for Service setup:"

var svcEnvHelp = map[string]string{
	"SERVICE_USERNAME": "The service username as configured in AAS",
	"SERVICE_PASSWORD": "The service password as configured in AAS",
}

const svcEnvHelpPrompt2 = "Following generic environment variables are required for Service setup:"

var svcEnvHelp2 = map[string]string{
	"AAS_BASE_URL":         "The url to AAS",
	"CMS_BASE_URL":         "The url to CMS",
	"CMS_TLS_CERT_SHA384":  "The certificate sha384 digest of CMS",
}

func (t *ServiceSetup) Run() error {
	if t.SvcConfigPtr == nil ||
		t.AASApiUrlPtr == nil ||
		t.CMSBaseURLPtr == nil ||
		t.CmsTlsCertDigestPtr == nil {
		return errors.New("Pointer to service configuration structure can not be nil")
	}
	if t.Username == "" {
		return errors.New("HVS configuration not provided: HVS_SERVICE_USERNAME is not set")
	}
	if t.Password == "" {
		return errors.New("HVS configuration not provided: HVS_SERVICE_PASSWORD is not set")
	}
	if t.AASApiUrl == "" {
		return errors.New("HVS configuration not provided: AAS_BASE_URL is not set")
	}
	if t.CMSBaseURL == "" {
		return errors.New("HVS configuration not provided: CMS_BASE_URL is not set")
	}
	if t.CmsTlsCertDigest == "" {
		return errors.New("HVS configuration not provided: CMS_TLS_CERT_SHA384 is not set")
	}
	t.SvcConfigPtr.Username = t.Username
	t.SvcConfigPtr.Password = t.Password
	*t.AASApiUrlPtr = t.AASApiUrl
	*t.CMSBaseURLPtr = t.CMSBaseURL
	*t.CmsTlsCertDigestPtr = t.CmsTlsCertDigest
	return nil
}

func (t *ServiceSetup) Validate() error {
	if t.SvcConfigPtr == nil ||
		t.AASApiUrlPtr == nil ||
		t.CMSBaseURLPtr == nil ||
		t.CmsTlsCertDigestPtr == nil {
		return errors.New("Pointer to service configuration structure can not be nil")
	}
	if t.SvcConfigPtr.Username == "" ||
		t.SvcConfigPtr.Password == "" ||
		*t.AASApiUrlPtr == "" ||
		*t.CMSBaseURLPtr == "" ||
		*t.CmsTlsCertDigestPtr == "" {
		return errors.New("Configured service username/password is not valid")
	}
	return nil
}

func (t *ServiceSetup) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, svcEnvHelpPrompt, t.envPrefix, svcEnvHelp)
	PrintEnvHelp(w, svcEnvHelpPrompt2, "", svcEnvHelp2)
	fmt.Fprintln(w, "")
}

func (t *ServiceSetup) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = PrefixUnderscroll(e)
}
