/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"github.com/intel-secl/intel-secl/v3/pkg/aas/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"os"
)

// Configuration is the global configuration struct that is marshalled/unmarshalled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	CMSBaseURL       string                   `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	CmsTlsCertDigest string                   `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`
	AAS              AASConfig                `yaml:"aas" mapstructure:"aas"`
	DB               commConfig.DBConfig      `yaml:"db" mapstructure:"db"`
	Log              commConfig.LogConfig     `yaml:"log" mapstructure:"log"`
	AuthDefender     AuthDefender             `yaml:"auth-defender" mapstructure:"auth-defender"`
	JWT              JWT                      `yaml:"jwt" mapstructure:"jwt"`
	TLS              commConfig.TLSCertConfig `yaml:"tls" mapstructure:"tls"`
	Server           commConfig.ServerConfig  `yaml:"server" mapstructure:"server"`
}

type AASConfig struct {
	Username string `yaml:"service-username" mapstructure:"service-username"`
	Password string `yaml:"service-password" mapstructure:"service-password"`
}

type JWT struct {
	IncludeKid        bool   `yaml:"include-kid" mapstructure:"include-kid"`
	TokenDurationMins int    `yaml:"token-duration-mins" mapstructure:"token-duration-mins"`
	CertCommonName    string `yaml:"cert-common-name" mapstructure:"cert-common-name"`
}

type AuthDefender struct {
	MaxAttempts         int `yaml:"max-attempts" mapstructure:"max-attempts"`
	IntervalMins        int `yaml:"interval-mins" mapstructure:"interval-mins"`
	LockoutDurationMins int `yaml:"lockout-duration-mins" mapstructure:"lockout-duration-mins"`
}

// this function sets the configuration file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

func (conf *Configuration) Save(filename string) error {
	configFile, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer configFile.Close()
	err = yaml.NewEncoder(configFile).Encode(conf)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}

func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}
