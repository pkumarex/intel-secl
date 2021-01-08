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

var defaultFlavorTemplateNames = []string{
	"default-linux-tpm20-tboot",
	"default-linux-tpm20-suefi",
	"default-linux-tpm20-cbnt",
	"default-uefi",
	"default-bmc",
	"default-pfr",
}

func (t *CreateDefaultTemplate) Run() error {
	var templates []hvs.FlavorTemplate

	ftStore, err := t.flavorTemplateStore()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize flavor template store instance")
	}

	if len(t.deleted) != 0 {
		// Recover deleted default template.
		err := ftStore.Recover(t.deleted)
		if err != nil {
			return errors.Wrapf(err, "Failed to recover default flavor template(s) %s", t.deleted)
		}
		t.deleted = []string{}
		return nil
	}

	templates, err = getTemplates()
	if err != nil {
		return err
	}

	for _, ft := range templates {
		_, err := ftStore.Create(&ft)
		if err != nil {
			return errors.Wrap(err, "Failed to create default flavor template with ID \""+ft.ID.String()+"\"")
		}
	}

	return nil
}

func (t *CreateDefaultTemplate) Validate() error {
	ftStore, err := t.flavorTemplateStore()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize flavor template store instance")
	}
	var ftList []hvs.FlavorTemplate
	defaultFlavorTemplateMap := map[string]bool{}
	t.deleted = []string{}

	for _, templateName := range defaultFlavorTemplateNames {
		defaultFlavorTemplateMap[templateName] = false
	}

	ftList, err = ftStore.Search(false)
	if err != nil {
		return errors.Wrap(err, "Failed to validate "+t.commandName)
	}
	if len(ftList) == 0 {
		return errors.New("No active templates found in db")
	}

	for _, template := range ftList {
		defaultFlavorTemplateMap[template.Label] = true
	}

	for _, templateName := range defaultFlavorTemplateNames {
		if !defaultFlavorTemplateMap[templateName] {
			t.deleted = append(t.deleted, templateName)
		}
	}

	if len(t.deleted) != 0 {
		return errors.New(t.commandName + ": Failed to create default flavor template(s) \"" + strings.Join(t.deleted, " "))
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
			return nil, errors.Wrap(err, "Failed to connect database")
		}
		t.TemplateStore = postgres.NewFlavorTemplateStore(dataStore)
	}
	if t.TemplateStore.Store == nil {
		return nil, errors.New("Failed to create FlavorTemplateStore")
	}
	return t.TemplateStore, nil
}

func getTemplates() ([]hvs.FlavorTemplate, error) {
	var ret []hvs.FlavorTemplate

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

var defaultFlavorTemplatesRaw = []string{
	`{
		"label": "default-linux-tpm20-tboot",
		"condition": [
			"//host_info/os_name//*[text()='RedHatEnterprise']",
			"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
			"//host_info/tboot_installed//*[text()='true']"
		],
		"flavor_parts": {
			"PLATFORM": {
				"meta": {
					"tpm_version": "2.0",
					"tboot_installed": true
				},
				"pcr_rules": [
					{
					"pcr": {
							"index": 0,
							"bank": "SHA256"
					},
					"pcr_matches": true
					},
					{
						"pcr": {
							"index": 17,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_equals": {
							"excluding_tags": [
								"LCP_CONTROL_HASH",
								"initrd",
								"vmlinuz"
							]
						}
					},
					{
						"pcr": {
							"index": 18,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_equals": {
							"excluding_tags": [
								"LCP_CONTROL_HASH",
								"initrd",
								"vmlinuz"
							]
						}
					}
				]
			},
			"OS": {
				"meta": {
					"tpm_version": "2.0",
					"tboot_installed": true
				},
				"pcr_rules": [
					{
						"pcr": {
							"index": 17,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_includes": [
							"vmlinuz"
						]
					}
				]
			},
			"HOST_UNIQUE": {
				"meta": {
					"tpm_version": "2.0",
					"tboot_installed": true
				},
				"pcr_rules": [
					{
						"pcr": {
							"index": 17,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_includes": [
							"LCP_CONTROL_HASH",
							"initrd"
						]
					},
					{
						"pcr": {
							"index": 18,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_includes": [
							"LCP_CONTROL_HASH"
						]
					}
				]
			}
		}
	}
	`,
	`{
		"label": "default-linux-tpm20-suefi",
		"condition": [
			"//host_info/os_name//*[text()='RedHatEnterprise']",
			"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
			"//host_info/hardware_features/UEFI/meta/secure_boot_enabled//*[text()='true']"
		],
		"flavor_parts": {
			"PLATFORM": {
				"meta": {
					"tpm_version": "2.0",
					"suefi_enabled": true
				},
				"pcr_rules": [
					{
						"pcr": {
							"index": 0,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 1,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 2,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 3,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 4,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 5,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 6,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 7,
							"bank": "SHA256"
						},
						"pcr_matches": true
					}
				]
			}
		}
	}
	`,
	`{
		"label": "default-linux-tpm20-cbnt",
		"condition": [
			"//host_info/os_name//*[text()='RedHatEnterprise']",
			"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
			"//host_info/hardware_features/CBNT/enabled//*[text()='true']"
		],
		"flavor_parts": {
			"PLATFORM": {
				"meta": {
					"tpm_version": "2.0",
					"cbnt_enabled": true
				},
				"pcr_rules": [
					{
						"pcr": {
							"index": 0,
							"bank": "SHA256"
						},
						"pcr_matches": true
					},
					{
						"pcr": {
							"index": 7,
							"bank": "SHA256"
						},
						"pcr_matches": true
					}
				]
			}
		}
	}
	`,
	`{
		"label": "default-uefi",
		"condition": [
			"//host_info/os_name//*[text()='RedHatEnterprise']",
			"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
			"//host_info/hardware_features/UEFI/enabled//*[text()='true'] or //host_info/hardware_features/UEFI/meta/secure_boot_enabled//*[text()='true']"
		],
		"flavor_parts": {
			"PLATFORM": {
				"meta": {
					"vendor": "Linux",
					"tpm_version": "2.0",
					"uefi_enabled": true
				},
				"pcr_rules": [{
					"pcr": {
						"index": 0,
						"bank": "SHA256"
					},
					"pcr_matches": true,
					"eventlog_equals": {}
				}]
			},
			"OS": {
				"meta": {
					"vendor": "Linux",
					"tpm_version": "2.0",
					"uefi_enabled": true
				},
				"pcr_rules": [{
					"pcr": {
						"index": 7,
						"bank": "SHA256"
					},
					"pcr_matches": true,
					"eventlog_includes": [
						"shim", "db", "kek", "vmlinuz"
					]
				}]
			}
		}
	}`,
	`{
		"label": "default-bmc",
		"condition": [
			"//host_info/os_name//*[text()='RedHatEnterprise']",
			"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
			"//SHA256/*[./pcr/index/text()=0 and ./tpm_events/*/tags/*/text()='Firmware Hash']"
		],
		"flavor_parts": {
			"PLATFORM": {
				"meta": {
					"vendor":"Linux",
					"tpm_version": "2.0",
					"bmc_enabled": true
				},
				"pcr_rules": [
					{
						"pcr": {
							"index": 0,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_includes": [
							"Firmware Hash"
						]
					}
				]
			}
		}
	}
	`,
	`{
		"label": "default-pfr",
		"condition": [
			"//host_info/os_name//*[text()='RedHatEnterprise']",
			"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']",
			"//SHA256/*[./pcr/index/text()=0 and ./tpm_events/*/tags/*/text()='Intel PFR']"
		],
		"flavor_parts": {
			"PLATFORM": {
				"meta": {
					"vendor":"Linux",
					"tpm_version": "2.0",
					"pfr_enabled": true
				},
				"pcr_rules": [
					{
						"pcr": {
							"index": 0,
							"bank": "SHA256"
						},
						"pcr_matches": true,
						"eventlog_includes": [
							"Intel PFR"
						]
					}
				]
			}
		}
	}`,
}
