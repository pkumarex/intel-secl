/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"os"
)

// Configuration is the global configuration struct that is marshalled/unmarshalled to a persisted yaml file
type Configuration struct {
	Log               commConfig.LogConfig    `yaml:"log" mapstructure:"log"`
	AASApiUrl         string                  `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CACert            CACertConfig            `yaml:"cms-ca" mapstructure:"cms-ca"`
	TlsCertDigest     string                  `yaml:"tls-cert-digest" mapstructure:"tls-cert-digest"`
	TlsSanList        string                  `yaml:"san-list" mapstructure:"san-list"`
	TokenDurationMins int                     `yaml:"token-duration-mins" mapstructure:"token-duration-mins"`
	Server            commConfig.ServerConfig `yaml:"server" mapstructure:"server"`
	AasJwtCn          string                  `yaml:"aas-jwt-cn" mapstructure:"aas-jwt-cn"`
	AasTlsCn          string                  `yaml:"aas-tls-cn" mapstructure:"aas-tls-cn"`
	AasTlsSan         string                  `yaml:"aas-tls-san" mapstructure:"aas-tls-san"`
}

type CACertConfig struct {
	Validity     int    `yaml:"cert-validity" mapstructure:"cert-validity"`
	Organization string `yaml:"organization" mapstructure:"organization"`
	Locality     string `yaml:"locality" mapstructure:"locality"`
	Province     string `yaml:"province" mapstructure:"province"`
	Country      string `yaml:"country" mapstructure:"country"`
}

// this function sets the configuration file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

func (c *Configuration) Save(filename string) error {
	configFile, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing config file")
		}
	}()
	err = yaml.NewEncoder(configFile).Encode(c)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}

func Load() (*Configuration, error) {
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
