/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"fmt"
	"io"

	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
)

type ServerSetup struct {
	commConfig.ServerConfig

	SvrConfigPtr  *commConfig.ServerConfig
	ConsoleWriter io.Writer

	DefaultPort int
	envPrefix   string
	commandName string
}

const svrEnvHelpPrompt = "Following environment variables are required for Server setup:"

var svrEnvHelp = map[string]string{
	"SERVER_PORT":                "The port on which to listen",
	"SERVER_READ_TIMEOUT":        "Service Read Timeout",
	"SERVER_READ_HEADER_TIMEOUT": "Service Read Header Timeout",
	"SERVER_WRITE_TIMEOUT":       "Service Write Timeout",
	"SERVER_IDLE_TIMEOUT":        "Service Idle Timeout",
	"SERVER_MAX_HEADER_BYTES":    "Max Header Bytes",
}

func (t *ServerSetup) Run() error {
	if t.SvrConfigPtr == nil {
		return errors.New("Pointer to server configuration structure can not be nil")
	}
	if t.Port < 1024 ||
		t.Port > 65535 {
		t.Port = t.DefaultPort
	}
	t.SvrConfigPtr.Port = t.Port
	t.SvrConfigPtr.ReadTimeout = t.ReadTimeout
	t.SvrConfigPtr.ReadHeaderTimeout = t.ReadHeaderTimeout
	t.SvrConfigPtr.WriteTimeout = t.WriteTimeout
	t.SvrConfigPtr.IdleTimeout = t.IdleTimeout
	t.SvrConfigPtr.MaxHeaderBytes = t.MaxHeaderBytes
	return nil
}

func (t *ServerSetup) Validate() error {
	if t.SvrConfigPtr == nil {
		return errors.New("Pointer to server configuration structure can not be nil")
	}
	if t.SvrConfigPtr.Port < 1024 ||
		t.SvrConfigPtr.Port > 65535 {
		return errors.New("Configured port is not valid")
	}
	return nil
}

func (t *ServerSetup) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, svrEnvHelpPrompt, t.envPrefix, svrEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *ServerSetup) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = PrefixUnderscroll(e)
}
