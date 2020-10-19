/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"net/url"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/pkg/errors"
)

const MaxQueryParamsLength = 50

var defaultLog = log.GetDefaultLogger()

func ValidateQueryParams(params url.Values, validQueries map[string]bool) error {
	defaultLog.Trace("utils/controller:ValidateQueryParams() Entering")
	defer defaultLog.Trace("utils/controller:ValidateQueryParams() Leaving")

	if len(params) > MaxQueryParamsLength {
		return errors.New("Invalid query parameters provided. Number of query parameters exceeded maximum value")
	}
	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return errors.New("Invalid query parameter provided. Refer to product guide for details.")
		}
	}
	return nil
}
