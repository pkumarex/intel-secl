/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto/x509/pkix"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hrrs"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/tasks"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, s := range args {
		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
				break
			} else {
				return errors.New("Invalid answer file name")
			}
		}
		if s == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := a.setupTaskRunner()
	if err != nil {
		return err
	}
	defer a.Config.Save(constants.DefaultConfigFilePath)
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			runner.PrintAllHelp()
		} else {
			runner.PrintHelp(cmd)
		}
		return nil
	}
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(a.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(a.errorWriter(), errCmd+": "+failErr.Error())
				runner.PrintHelp(errCmd)
			}
			return errors.New("Failed to run all tasks")
		}
		fmt.Fprintln(a.consoleWriter(), "All setup tasks succeeded")
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), cmd+": "+err.Error())
			runner.PrintHelp(cmd)
			return errors.New("Failed to run setup task " + cmd)
		}
	}
	return a.configDirChown()
}

// a helper function for setting up the task runner
func (a *App) setupTaskRunner() (*setup.Runner, error) {

	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if a.configuration() == nil {
		a.Config = defaultConfig()
	}
	a.setupHRRSConfig()

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	runner.AddTask("server", "", &setup.ServerSetup{
		SvrConfigPtr: &a.Config.Server,
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		ConsoleWriter: a.consoleWriter(),
		DefaultPort:   constants.DefaultHVSListenerPort,
	})
	runner.AddTask("service", "", &tasks.ServiceSetup{
		SvcConfigPtr:        &a.Config.HVS,
		AASApiUrlPtr:        &a.Config.AASApiUrl,
		CMSBaseURLPtr:       &a.Config.CMSBaseURL,
		CmsTlsCertDigestPtr: &a.Config.CmsTlsCertDigest,
		HVSConfig: config.HVSConfig{
			Username: viper.GetString("hvs-service-username"),
			Password: viper.GetString("hvs-service-password"),
		},
		AASApiUrl:        viper.GetString("aas-base-url"),
		CMSBaseURL:       viper.GetString("cms-base-url"),
		CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
		ConsoleWriter:    a.consoleWriter(),
	})
	dbConf := commConfig.DBConfig{
		Vendor:   viper.GetString("db-vendor"),
		Host:     viper.GetString("db-host"),
		Port:     viper.GetInt("db-port"),
		DBName:   viper.GetString("db-name"),
		Username: viper.GetString("db-username"),
		Password: viper.GetString("db-password"),
		SSLMode:  viper.GetString("db-ssl-mode"),
		SSLCert:  viper.GetString("db-ssl-cert"),

		ConnectionRetryAttempts: viper.GetInt("db-conn-retry-attempts"),
		ConnectionRetryTime:     viper.GetInt("db-conn-retry-time"),
	}
	runner.AddTask("database", "", &tasks.DBSetup{
		DBConfigPtr:   &a.Config.DB,
		DBConfig:      dbConf,
		SSLCertSource: viper.GetString("db-ssl-cert-source"),
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("create-default-flavorgroup", "", &tasks.CreateDefaultFlavor{
		DBConfig: dbConf,
	})
	runner.AddTask("create-dek", "", &tasks.CreateDek{
		DekStore: &a.Config.HVS.Dek,
	})
	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedRootCACertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		TlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
	})
	runner.AddTask("download-cert-tls", "tls", &setup.DownloadCert{
		KeyFile:      viper.GetString("tls-key-file"),
		CertFile:     viper.GetString("tls-cert-file"),
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString("tls-common-name"),
		},
		SanList:       viper.GetString("tls-san-list"),
		CertType:      "tls",
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	})
	runner.AddTask("download-cert-saml", "saml", a.downloadCertTask("saml"))
	runner.AddTask("download-cert-flavor-signing", "flavor-signing", a.downloadCertTask("flavor-signing"))

	runner.AddTask("create-privacy-ca", "privacy-ca", a.selfSignTask("privacy-ca"))
	runner.AddTask("create-endorsement-ca", "endorsement-ca", a.selfSignTask("endorsement-ca"))
	runner.AddTask("create-tag-ca", "tag-ca", a.selfSignTask("tag-ca"))
	runner.AddTask("create-default-template", "", &tasks.CreateDefaultTemplate{
		DBConf: dbConf,
	})

	return runner, nil
}

func (a *App) downloadCertTask(certType string) setup.Task {
	certTypeReq := certType
	var updateConfig *commConfig.SigningCertConfig
	switch certType {
	case "saml":
		updateConfig = &a.configuration().SAML.CommonConfig
		certTypeReq = "signing"
	case "flavor-signing":
		updateConfig = &a.configuration().FlavorSigning
	}
	updateConfig.KeyFile = viper.GetString(certType + "-key-file")
	updateConfig.CertFile = viper.GetString(certType + "-cert-file")
	updateConfig.CommonName = viper.GetString(certType + "-common-name")
	return &setup.DownloadCert{
		KeyFile:      viper.GetString(certType + "-key-file"),
		CertFile:     viper.GetString(certType + "-cert-file"),
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(certType + "-common-name"),
		},
		CertType:      certTypeReq,
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	}
}

func (a *App) selfSignTask(name string) setup.Task {
	var updateConfig *commConfig.SelfSignedCertConfig
	switch name {
	case "privacy-ca":
		updateConfig = &a.configuration().PrivacyCA
	case "endorsement-ca":
		updateConfig = &a.configuration().EndorsementCA
	case "tag-ca":
		updateConfig = &a.configuration().TagCA
	}
	if updateConfig != nil {
		updateConfig.KeyFile = viper.GetString(name + "-key-file")
		updateConfig.CertFile = viper.GetString(name + "-cert-file")
		updateConfig.CommonName = viper.GetString(name + "-common-name")
		updateConfig.Issuer = viper.GetString(name + "-issuer")
		updateConfig.ValidityDays = viper.GetInt(name + "-validity-years")
	}
	return &setup.SelfSignedCert{
		CertFile:     viper.GetString(name + "-cert-file"),
		KeyFile:      viper.GetString(name + "-key-file"),
		CommonName:   viper.GetString(name + "-common-name"),
		Issuer:       viper.GetString(name + "-issuer"),
		SANList:      viper.GetString(name + "-san-list"),
		ValidityDays: viper.GetInt(name + "-validity-years"),

		ConsoleWriter: a.consoleWriter(),
	}
}

// The HRRS does not require setup, just one configuration parameter.  This function
// populates the HRRS config during 'hvs setup'.
//
// The function needs to handle...
// - The first run of setup with new a config.  The config will either have the default
//   values (from defaultConfig()) or custom values from env/answer file.
// - Setup is being re-run and the config has been previously populated (from 'new')...
//   - User has provided custom HRRS env/answer file values
//     ==> These should be applied to the config
//   - User has NOT provided custom HRRS env/answer file values
//     ==> Any previously configured custom values should be maintained
//
// This logic can achieved by just applying custom env/answer file values when they
// are different from the defaults.
func (a *App) setupHRRSConfig() {

	refreshPeriod := viper.GetDuration(hrrsRefreshPeriod)
	if refreshPeriod != hrrs.DefaultRefreshPeriod {
		a.Config.HRRS.RefreshPeriod = refreshPeriod
	}
}

func (a *App) configDirChown() error {
	svcUser, err := user.Lookup(constants.ServiceUserName)
	if err != nil {
		return errors.Wrapf(err, "configDirChown: could not find user '%s'", constants.ServiceUserName)
	}
	uid, err := strconv.Atoi(svcUser.Uid)
	if err != nil {
		return errors.Wrapf(err, "configDirChown: could not parse aas user uid '%s'", svcUser.Uid)
	}
	gid, err := strconv.Atoi(svcUser.Gid)
	if err != nil {
		return errors.Wrapf(err, "configDirChown: could not parse aas user gid '%s'", svcUser.Gid)
	}
	err = cos.ChownR(a.configDir(), uid, gid)
	if err != nil {
		return errors.Wrap(err, "Error while changing ownership of files inside config directory")
	}
	return nil
}
