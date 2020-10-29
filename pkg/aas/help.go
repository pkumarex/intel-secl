/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v3/pkg/aas/version"
)

const helpStr = `Usage:
	authservice <command> [arguments]

Available Commands:
	-h|--help              Show this help message
	setup <task>           Run setup task
	start                  Start authservice
	status                 Show the status of authservice
	stop                   Stop authservice
	tlscertsha384          Show the SHA384 digest of the certificate used for TLS
	uninstall [--purge]    Uninstall authservice. --purge option needs to be applied to remove configuration and data files
	-v|--version           Show the version of authservice

	Setup command usage:       authservice setup [task] [--arguments=<argument_value>] [--force]
	Available Tasks for setup:
		all                   Runs all setup tasks
		download-ca-cert      Download CMS root CA certificate
		download-cert-tls     Download CA certificate from CMS for tls
		jwt                   Create jwt signing key and jwt certificate signed by CMS
		server                Setup http server on given port
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), "Auth Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
}
