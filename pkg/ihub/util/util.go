/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"time"
)

var defaultLog = log.GetDefaultLogger()

func EvaluateValidTo(validTo time.Time, minutes int) time.Time {
	defaultLog.Trace("util:EvaluateValidTo() Entering")
	defer defaultLog.Trace("util:EvaluateValidTo() Leaving")

	twiceSchedulerTime := minutes * 2
	updatedTime := time.Now().UTC().Add(time.Minute * time.Duration(twiceSchedulerTime))

	if validTo.After(updatedTime) {
		return validTo
	} else {
		return updatedTime
	}
}
