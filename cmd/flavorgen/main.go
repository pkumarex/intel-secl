/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/flavorgen"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/setup"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var LogWriter io.Writer
var defaultLog = commLog.GetDefaultLogger()

const LogFile = "flavorgen.log"

func openLogFiles() (logFile *os.File, err error) {

	logFile, err = os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(LogFile, 0664); err != nil {
		return nil, err
	}

	return logFile, nil
}

func configureLogs() error {
	var ioWriterDefault io.Writer
	ioWriterDefault = LogWriter

	loglevel := "debug"
	parsedLevel, err := logrus.ParseLevel(loglevel)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+loglevel)
	}
	formattedLog := commLog.LogFormatter{MaxLength: 300}
	commLogInt.SetLogger(commLog.DefaultLoggerName, parsedLevel, &formattedLog, ioWriterDefault, false)

	defaultLog.Info(commLogMsg.LogInit)

	return nil
}

func main() {
	logs, err := openLogFiles()
	if err != nil {
		fmt.Println("Failed to initialize logs")
		LogWriter = os.Stdout
	}
	LogWriter = logs
	configureLogs()
	var flavorGen flavorgen.FlavorGen
	flavorGen.GenerateFlavors()
}
