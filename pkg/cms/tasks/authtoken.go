/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/pem"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	jwtauth "github.com/intel-secl/intel-secl/v3/pkg/lib/common/jwt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	ct "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/pkg/errors"
	"io"
	"os"
	"time"
)

type CmsAuthToken struct {
	ConsoleWriter io.Writer
	AasTlsCn      string
	AasJwtCn      string
	AasTlsSan     string
	TokenDuration int
	envPrefix     string
	commandName   string
}

const authTokenEnvHelpPrompt = "Following environment variables are required for authToken setup:"

var authTokenEnvHelp = map[string]string{
	"AAS_JWT_CN":  "Common Name for JWT Signing Certificate used in Authentication and Authorization Service",
	"AAS_TLS_CN":  "Common Name for TLS Signing Certificate used in  Authentication and Authorization Service",
	"AAS_TLS_SAN": "TLS SAN list for Authentication and Authorization Service",
}

func createCmsAuthToken(at CmsAuthToken) (err error) {
	log.Trace("tasks/authtoken:createCmsAuthToken() Entering")
	defer log.Trace("tasks/authtoken:createCmsAuthToken() Leaving")

	cert, key, err := crypt.CreateKeyPairAndCertificate("CMS JWT Signing", "", constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not create CMS JWT certificate")
	}

	err = crypt.SavePrivateKeyAsPKCS8(key, constants.TrustedJWTSigningCertsDir+constants.TokenKeyFile)
	if err != nil {
		return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not save CMS JWT private key")
	}
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	err = crypt.SavePemCertWithShortSha1FileName(certPemBytes, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not save CMS JWT certificate")
	}
	fmt.Fprintln(at.ConsoleWriter, "Running CMS generate JWT token setup...")

	factory, err := jwtauth.NewTokenFactory(key, true, certPemBytes, "CMS JWT Signing", time.Duration(at.TokenDuration)*time.Minute)
	if err != nil {
		return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not get instance of Token factory")
	}

	ur := []ct.RoleInfo{
		{"CMS", constants.CertApproverGroupName, "CN=" + at.AasJwtCn + ";CERTTYPE=JWT-Signing"},
		{"CMS", constants.CertApproverGroupName, "CN=" + at.AasTlsCn + ";SAN=" + at.AasTlsSan + ";CERTTYPE=TLS"},
	}
	claims := ct.RoleSlice{ur}

	log.Infof("tasks/authtoken:Run() AAS setup JWT token claims - %v", claims)
	jwt, err := factory.Create(&claims, "CMS JWT Token", 0)
	if err != nil {
		return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not create CMS JWT token")
	}
	fmt.Println("\nJWT Token:", jwt)
	return
}

func (at CmsAuthToken) Run() error {
	log.Trace("tasks/authtoken:Run() Entering")
	defer log.Trace("tasks/authtoken:Run() Leaving")

	fmt.Fprintln(at.ConsoleWriter, "Running auth token setup...")

	err := createCmsAuthToken(at)
	if err != nil {
		return errors.Wrap(err, "tasks/authtoken:Run() Could not create CMS JWT token")
	}

	return nil
}

func (at CmsAuthToken) Validate() error {
	log.Trace("tasks/authtoken:Validate() Entering")
	defer log.Trace("tasks/authtoken:Validate() Leaving")

	fmt.Fprintln(at.ConsoleWriter, "Validating auth token setup...")
	_, err := os.Stat(constants.TrustedJWTSigningCertsDir + constants.TokenKeyFile)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/authtoken:Validate() Auth Token is not configured")
	}
	return nil
}

func (at CmsAuthToken) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, authTokenEnvHelpPrompt, at.envPrefix, authTokenEnvHelp)
	fmt.Fprintln(w, "")
}

func (at CmsAuthToken) SetName(n, e string) {
	at.commandName = n
	at.envPrefix = setup.PrefixUnderscroll(e)
}
