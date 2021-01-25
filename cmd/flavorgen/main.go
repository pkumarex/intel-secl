/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"
    "os/user"
	"strconv"
	"github.com/intel-secl/intel-secl/v3/pkg/flavorgen"
	
)

func openLogFiles() (logFile *os.File, err error) {

	logFile, err = os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(LogFile, 0664); err != nil {
		return nil,err
	}

	flavorgenUser, err := user.Lookup(ServiceUserName)
	if err != nil {
		return nil,fmt.Errorf("Could not find user '%s'", ServiceUserName)
	}


	uid, err := strconv.Atoi(flavorgenUser.Uid)
	if err != nil {
		return nil, fmt.Errorf("Could not parse hvs user uid '%s'", flavorgenUser.Uid)
	}

	gid, err := strconv.Atoi(flavorgenUser.Gid)
	if err != nil {
		return nil, fmt.Errorf("Could not parse hvs user gid '%s'", flavorgenUser.Gid)
	}

	err = os.Chown(LogFile, uid, gid)
	if err != nil {
		return nil, fmt.Errorf("Could not change file ownership for file: '%s'", LogFile)
	}
	return
}

func main() {
	l,err := openLogFiles()
	var app *flavorgen.App
	if err != nil {
		app = &flavorgen.App{
			LogWriter: os.Stdout,
		}
	} else {
		defer func() {
			err = l.Close()
			if err != nil {
				fmt.Println("Failed close log file:", err.Error())
			}
		}()
		app = &flavorgen.App{
			LogWriter:     l,
		}
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error:", err.Error())
		os.Exit(1)
	}
}
