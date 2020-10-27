/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/cms/config"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.TLSCertPath)
	viper.SetDefault("tls-key-file", constants.TLSKeyPath)
	viper.SetDefault("san-list", constants.DefaultTlsSan)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

	viper.SetDefault("cms-ca-cert-validity", constants.DefaultCACertValidity)
	viper.SetDefault("cms-ca-organization", constants.DefaultOrganization)
	viper.SetDefault("cms-ca-locality", constants.DefaultLocality)
	viper.SetDefault("cms-ca-province", constants.DefaultProvince)
	viper.SetDefault("cms-ca-country", constants.DefaultCountry)

	viper.SetDefault("aas-tls-cn", constants.DefaultAasTlsCn)
	viper.SetDefault("aas-jwt-cn", constants.DefaultAasJwtCn)
	viper.SetDefault("aas-tls-san", constants.DefaultTlsSan)

	viper.SetDefault("token-duration-mins", constants.DefaultTokenDurationMins)
}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASApiUrl: viper.GetString("aas-base-url"),
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
		CACert: config.CACertConfig{
			Validity:     viper.GetInt("cms-ca-cert-validity"),
			Organization: viper.GetString("cms-ca-organization"),
			Locality:     viper.GetString("cms-ca-locality"),
			Province:     viper.GetString("cms-ca-province"),
			Country:      viper.GetString("cms-ca-country"),
		},
		AasJwtCn:          viper.GetString("aas-jwt-cn"),
		AasTlsCn:          viper.GetString("aas-tls-cn"),
		AasTlsSan:         viper.GetString("aas-tls-san"),
		TlsSanList:        viper.GetString("san-list"),
		TokenDurationMins: viper.GetInt("token-duration-mins"),
	}
}

func loadAlias() {
	alias := map[string]string{
		"server-port":                "CMS_PORT",
		"server-read-timeout":        "CMS_SERVER_READ_TIMEOUT",
		"server-read-header-timeout": "CMS_SERVER_READ_HEADER_TIMEOUT",
		"server-write-timeout":       "CMS_SERVER_WRITE_TIMEOUT",
		"server-idle-timeout":        "CMS_SERVER_IDLE_TIMEOUT",
		"server-max-header-bytes":    "CMS_SERVER_MAX_HEADER_BYTES",
		"log-enable-stdout":          "CMS_ENABLE_CONSOLE_LOG",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
