/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/pkg/errors"
)

type CreateDefaultTransferPolicy struct {
	ConsoleWriter             io.Writer
	DefaultTransferPolicyFile string
	commandName               string
}

func (t *CreateDefaultTransferPolicy) Run() error {
	fmt.Fprintln(t.ConsoleWriter, "Creating default key transfer policy")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return errors.Wrap(err, "tasks/create_default_transfer_policy:Run() failed to create new UUID")
	}
	defaultTransferPolicy := models.DefaultTransferPolicy{
		ID:             newUuid,
		CreatedAt:      time.Now(),
		TransferPolicy: constants.DefaultTransferPolicy,
	}

	bytes, err := json.Marshal(defaultTransferPolicy)
	if err != nil {
		return errors.Wrap(err, "tasks/create_default_transfer_policy:Run() Failed to marshal DefaultTransferPolicy")
	}

	err = ioutil.WriteFile(t.DefaultTransferPolicyFile, bytes, 0600)
	if err != nil {
		return errors.Wrap(err, "tasks/create_default_transfer_policy:Run() Failed to store default key transfer policy in file")
	}

	fmt.Fprintln(t.ConsoleWriter, "Default key transfer policy created")
	return nil
}

func (t *CreateDefaultTransferPolicy) Validate() error {
	_, err := os.Stat(t.DefaultTransferPolicyFile)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_default_transfer_policy:Validate() default key transfer policy file does not exist")
	}
	return nil
}

func (t *CreateDefaultTransferPolicy) PrintHelp(w io.Writer) {
}

func (t *CreateDefaultTransferPolicy) SetName(n, e string) {
	t.commandName = n
}
