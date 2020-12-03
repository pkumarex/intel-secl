/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestLoadConfiguration(t *testing.T) {

	tests := []struct {
		name         string
		wantErr      bool
		configString string
		configFile   string
	}{

		{
			name:         "Test 1 Positive Case",
			wantErr:      false,
			configString: "pollintervalminutes: 5\n",
			configFile:   "config.yml",
		},
		{
			name:         "Test 2 Negative Case",
			wantErr:      true,
			configString: "pollintervalminutes: 5\n",
			configFile:   "",
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			dir, _ := ioutil.TempDir("", "")
			if tt.configFile != "" {
				f, _ := os.OpenFile(dir + "/" + tt.configFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
				f.WriteString("pollintervalminutes: 5\n")
				defer os.Remove(f.Name())
			}

			viper.AddConfigPath(dir)
			defer viper.Reset()

			_, err := LoadConfiguration()
			if (err != nil) != tt.wantErr {
				t.Errorf("config/config_test:TestLoadConfiguration() unable to load the config file: error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestSaveConfiguration(t *testing.T) {

	temp, err := ioutil.TempFile("", "config.yml")
	if err != nil {
		t.Log("config/config_test:TestSaveConfiguration() Error in creating temp file")
	}
	tests := []struct {
		name       string
		configFile string
		wantErr    bool
	}{

		{
			name:       "Test 1 Positive Case",
			configFile: temp.Name(),
			wantErr:    false,
		},
		{
			name:       "Test 2 Negative Case",
			configFile: "",
			wantErr:    true,
		},
		{
			name:       "Test 3 Negative Case",
			configFile: "X:/ee/etc/zz.yml",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			conf := Configuration{}
			conf.ConfigFile = tt.configFile

			err := conf.SaveConfiguration(tt.configFile)

			if (err != nil) != tt.wantErr {
				t.Errorf("config/config_test:TestConfiguration_Save() unable to save the config: error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}
