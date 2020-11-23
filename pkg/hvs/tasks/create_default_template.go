/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
)

type CreateDefaultTemplate struct {
	DBConf  commConfig.DBConfig
	deleted []string

	commandName   string
	TemplateStore *postgres.FlavorTemplateStore
}

func (t *CreateDefaultTemplate) Run() error {
	defaultTemplatesMap := make(map[string]string)
	var templates []hvs.FlavorTemplate

	ftStore, err := t.flavorTemplateStore()
	if err != nil {
		return err
	}

	templates, err = getMissingTemplates(t.deleted)
	if err != nil {
		return err
	}

	for _, ft := range templates {
		// create default flavortemplates ONLY if it does not exist already
		defaultTemplatesMap[ft.Label] = ft.ID.String()
		_, err := ftStore.Create(&ft)
		if err != nil {
			return errors.Wrap(err, "failed to create default flavor template with ID \""+ft.ID.String()+"\"")
		}
	}

	return nil
}

func (t *CreateDefaultTemplate) Validate() error {
	ftStore, err := t.flavorTemplateStore()
	if err != nil {
		return err
	}
	var ftList []hvs.FlavorTemplate
	availableTemplates := make(map[string]bool)
	t.deleted = []string{}

	for _, template := range defaultFlavorTemplateNames {
		availableTemplates[template] = false
	}

	ftList, err = ftStore.Search(false)
	if err != nil {
		return errors.Wrap(err, "Failed to validate "+t.commandName)
	}
	if ftList == nil {
		return errors.New("No active templates found in db")
	}

	for _, template := range ftList {
		availableTemplates[template.Label] = true
	}

	for _, templateName := range defaultFlavorTemplateNames {
		if !availableTemplates[templateName] {
			t.deleted = append(t.deleted, templateName)
		}
	}

	if len(t.deleted) != 0 {
		return errors.New(t.commandName + ": failed to create default flavor template(s) \"" + strings.Join(t.deleted, " "))
	}
	return nil
}

func (t *CreateDefaultTemplate) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, DbEnvHelpPrompt, "", DbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *CreateDefaultTemplate) SetName(n, e string) {
	t.commandName = n
}

func (t *CreateDefaultTemplate) flavorTemplateStore() (*postgres.FlavorTemplateStore, error) {
	var dataStore *postgres.DataStore
	var err error
	if t.TemplateStore == nil {
		dataStore, err = postgres.NewDataStore(postgres.NewDatabaseConfig(constants.DBTypePostgres, &t.DBConf))
		if err != nil {
			return nil, errors.Wrap(err, "failed to connect database")
		}
		t.TemplateStore = postgres.NewFlavorTemplateStore(dataStore)
	}
	if t.TemplateStore.Store == nil {
		return nil, errors.New("failed to create FlavorTemplateStore")
	}
	return t.TemplateStore, nil
}

func getMissingTemplates(unavailable []string) ([]hvs.FlavorTemplate, error) {
	var ret []hvs.FlavorTemplate
	templateMap := make(map[string]string)

	for i, name := range defaultFlavorTemplateNames {
		templateMap[name] = defaultFlavorTemplatesRaw[i]
	}

	if unavailable == nil {
		for _, ftStr := range defaultFlavorTemplatesRaw {
			var ft hvs.FlavorTemplate
			err := json.Unmarshal([]byte(ftStr), &ft)
			if err != nil {
				return nil, err
			}
			ret = append(ret, ft)
		}
		return ret, nil
	}

	for _, required := range unavailable {
		var ft hvs.FlavorTemplate
		err := json.Unmarshal([]byte(templateMap[required]), &ft)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ft)
	}

	return ret, nil
}

var defaultFlavorTemplateNames = []string{
	"default_uefi",
	"default_pfr",
	//"default_pfrr",
}

var defaultFlavorTemplatesRaw = []string{
	`{
	"label": "default_uefi",
	"condition": [
		"//meta/vendor='Linux'",
		"//meta/tpm_version/='2.0'",
		"//meta/uefi_enabled/='true' or //meta/suefi_enabled/='true'"
	],
	"flavor-parts": {
		"PLATFORM": {
			"meta": {
				"vendor": "Linux",
				"tpm_version": "2.0",
				"uefi_enabled": true
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 0,
						"bank": "SHA256"
					}
				}
			]
		},
		"OS": {
			"meta": {
				"vendor": "Linux",
				"tpm_version": "2.0",
				"uefi_enabled": true
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 7,
						"bank": "SHA256"
					},
					"eventlog_includes": [
						"shim",
						"db",
						"kek",
						"vmlinuz"
					]
				}
			]
		}
	}
}`,
	`{
	"label": "default_pfr",
	"condition": [
		"//meta/vendor='Linux'",
		"//meta/tpm_version/='2.0'" 
	],
	"flavor-parts": {
		"PLATFORM": {
			"meta": {
				"vendor":"Linux",
				"tpm_version": "2.0",
				"uefi_enabled": true
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 7,
						"bank": "SHA256"
					},
					"eventlog_includes": ["Inte PFR"]
				}
			]
		}
	}
}`,
}
