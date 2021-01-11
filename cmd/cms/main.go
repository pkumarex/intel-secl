/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {

	logFile, err = os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(LogFile, 0664)
	if err != nil {
		return nil, nil, nil, err
	}

	httpLogFile, err = os.OpenFile(HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(HTTPLogFile, 0664)
	if err != nil {
		return nil, nil, nil, err
	}

	secLogFile, err = os.OpenFile(SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(SecurityLogFile, 0664)
	if err != nil {
		return nil, nil, nil, err
	}

	cmsUser, err := user.Lookup(ServiceUserName)
	if err != nil {
		return nil, nil, nil, err
	}

	uid, err := strconv.Atoi(cmsUser.Uid)
	if err != nil {
		return nil, nil, nil, err
	}

	gid, err := strconv.Atoi(cmsUser.Gid)
	if err != nil {
		return nil, nil, nil, err
	}

	err = os.Chown(HTTPLogFile, uid, gid)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chown(SecurityLogFile, uid, gid)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chown(LogFile, uid, gid)
	if err != nil {
		return nil, nil, nil, err
	}

	return
}

func main() {
	var app *cms.App

	l, h, s, err := openLogFiles()
	if err != nil {
		app = &cms.App{
			LogWriter: os.Stdout,
		}
	} else {
		defer func() {
			err = l.Close()
			if err != nil {
				fmt.Println("Failed close log file:", err.Error())
			}
		}()
		defer func() {
			err = h.Close()
			if err != nil {
				fmt.Println("Failed close log file:", err.Error())
			}
		}()
		defer func() {
			err = s.Close()
			if err != nil {
				fmt.Println("Failed close log file:", err.Error())
			}
		}()
		app = &cms.App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error:", err.Error())
		os.Exit(1)
	}
}
