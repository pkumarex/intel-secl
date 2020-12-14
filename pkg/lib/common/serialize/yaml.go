/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v2"
)

// SaveToYamlFile saves input object to given file path
func SaveToYamlFile(path string, obj interface{}) error {

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	return yaml.NewEncoder(file).Encode(obj)
}

// LoadFromYamlFile loads yaml file on given path to an output object
// example: LoadFromYamlFile(configPath, &ConfigStruct{})
func LoadFromYamlFile(path string, out interface{}) error {

	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.UnmarshalStrict(yamlFile, out)
	if err != nil {
		return err
	}
	return nil
}
