/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/pkg/errors"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/setup"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	SecLogWriter   io.Writer
	ErrorWriter    io.Writer
}

func (app *App) Run(args []string) error {
	if len(args) < 2 {
		err := errors.New("Invalid usage of " + constants.ServiceName)
		app.printUsageWithError(err)
		return err
	}
	cmd := args[1]
	switch cmd {
	case "run":
		if len(args) != 2 {
			return errInvalidCmd
		}
		if err := app.startDaemon(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return errors.Wrap(err, "Error starting IHUB Service")
		}
	case "help", "-h", "--help":
		app.printUsage()
		return nil
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.status()
	case "uninstall":
		// the only allowed flag is --purge
		purge := false
		if len(args) == 3 {
			if args[2] != "--purge" {
				return errors.New("Invalid flag: " + args[2])
			}
			purge = true
		} else if len(args) != 2 {
			return errInvalidCmd
		}
		app.uninstall(purge)
		return nil
	case "version", "-v", "--version":
		app.printVersion()
		return nil
	case "setup":
		if err := app.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				app.printUsageWithError(err)
			} else {
				fmt.Fprintln(app.errorWriter(), err.Error())
			}
			return err
		}
	default:
		err := errors.New("Unrecognized command: " + cmd)
		app.printUsageWithError(err)
		return err
	}
	return nil
}

func (app *App) consoleWriter() io.Writer {
	if app.ConsoleWriter != nil {
		return app.ConsoleWriter
	}
	return os.Stdout
}

func (app *App) errorWriter() io.Writer {
	if app.ErrorWriter != nil {
		return app.ErrorWriter
	}
	return os.Stderr
}

func (app *App) secLogWriter() io.Writer {
	if app.SecLogWriter != nil {
		return app.SecLogWriter
	}
	return os.Stdout
}

func (app *App) logWriter() io.Writer {
	if app.LogWriter != nil {
		return app.LogWriter
	}
	return os.Stderr
}

func (app *App) configuration() *config.Configuration {
	if app.Config != nil {
		return app.Config
	}
	viper.AddConfigPath(app.configDir())
	c, err := config.LoadConfiguration()
	if err == nil {
		app.Config = c
		return app.Config
	}
	return nil
}

func (app *App) configureLogs(isStdOut bool, isFileOut bool) {

	var ioWriterDefault io.Writer
	ioWriterDefault = app.logWriter()
	if isStdOut {
		if isFileOut {
			ioWriterDefault = io.MultiWriter(os.Stdout, app.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, app.secLogWriter())

	logConfig := app.configuration().Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		fmt.Println("Failed to initiate loggers. Invalid log level: " + logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	log.Info(commLogMsg.LogInit)
}

func (app *App) start() error {

	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl start ihub"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "Could not locate systemctl to start service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "ihub"}, os.Environ())
}

func (app *App) stop() error {

	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl stop ihub"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "Could not locate systemctl to stop service")
	}
	//syscall does not return execution to the caller but replaces the current (Go) process with the process called, hence used exec
	cmd := exec.Command(systemctl, "stop", "ihub")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) status() error {

	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl status ihub"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "Could not locate systemctl to check status of service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "ihub"}, os.Environ())
}
