/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"github.com/intel-secl/intel-secl/v3/pkg/cms/constants"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

func GetNextSerialNumber() (*big.Int, error) {
	serialNumberNew, err := ReadSerialNumber()
	if err != nil && strings.Contains(err.Error(), "no such file") {
		serialNumberNew = big.NewInt(0)
		err = WriteSerialNumber(serialNumberNew)
		return serialNumberNew, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot write to Serial Number file")
	} else if err != nil {
		return nil, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot read from Serial Number file")
	} else {
		serialNumberNew = serialNumberNew.Add(serialNumberNew, big.NewInt(1))
		err = WriteSerialNumber(serialNumberNew)
		if err != nil {
			return nil, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot write to Serial Number file")
		}
		return serialNumberNew, nil
	}
}

func ReadSerialNumber() (*big.Int, error) {
	sn, err := ioutil.ReadFile(constants.SerialNumberPath)
	if err != nil {
		return nil, errors.Wrap(err, "utils/utils:ReadSerialNumber() Could not read serial number")
	} else {
		var serialNumber = big.NewInt(0)
		serialNumber.SetBytes(sn)
		return serialNumber, nil
	}
}

func WriteSerialNumber(serialNumber *big.Int) error {
	err := ioutil.WriteFile(constants.SerialNumberPath, serialNumber.Bytes(), 0660)
	if err != nil {
		return errors.Wrap(err, "utils/utils:WriteSerialNumber() Failed to write serial-number to file")
	}
	err = os.Chmod(constants.SerialNumberPath, 0660)
	if err != nil {
		return errors.Wrap(err, "utils/utils:WriteSerialNumber() Failed to update file permissions")
	}
	return nil
}
