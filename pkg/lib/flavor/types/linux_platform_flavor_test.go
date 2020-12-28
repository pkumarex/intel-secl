/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

const (
	ManifestPath       string = "../test/resources/HostManifest1.json"
	TagCertPath        string = "../test/resources/AssetTagpem.Cert"
	FlavorTemplatePath string = "../test/resources/TestTemplate.json"
)

var flavorTemplates []hvs.FlavorTemplate

func getFlavorTemplates(osName string, templatePath string) []hvs.FlavorTemplate {

	var template hvs.FlavorTemplate
	var templates []hvs.FlavorTemplate

	if strings.EqualFold(osName, "VMWARE ESXI") {
		return nil
	}

	// load hostmanifest
	if templatePath != "" {
		templateFile, _ := os.Open(templatePath)
		templateFileBytes, _ := ioutil.ReadAll(templateFile)
		_ = json.Unmarshal(templateFileBytes, &template)
		templates = append(templates, template)
	}
	return templates
}

func TestLinuxPlatformFlavor_GetPcrDetails(t *testing.T) {

	var hm *hcTypes.HostManifest
	var tagCert *cm.X509AttributeCertificate

	hmBytes, err := ioutil.ReadFile(ManifestPath)
	if err != nil {
		fmt.Println("flavor/util/linux_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read hostmanifest file : ", err)
	}

	err = json.Unmarshal(hmBytes, &hm)
	if err != nil {
		fmt.Println("flavor/util/linux_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall hostmanifest : ", err)
	}

	// load tag cert
	if TagCertPath != "" {
		// load tagCert
		// read the test tag cert
		tagCertFile, _ := os.Open(TagCertPath)
		tagCertPathBytes, _ := ioutil.ReadAll(tagCertFile)

		// convert pem to cert
		pemBlock, _ := pem.Decode(tagCertPathBytes)
		tagCertificate, _ := x509.ParseCertificate(pemBlock.Bytes)

		if tagCertificate != nil {
			tagCert, err = model.NewX509AttributeCertificate(tagCertificate)
			if err != nil {
				fmt.Println("flavor/util/linux_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() Error while generating X509AttributeCertificate from TagCertificate")
			}
		}
	}

	tagCertBytes, err := ioutil.ReadFile(TagCertPath)
	if err != nil {
		fmt.Println("flavor/util/linux_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to read tagcertificate file : ", err)
	}

	err = json.Unmarshal(tagCertBytes, &tagCert)
	if err != nil {
		fmt.Println("flavor/util/linux_platform_flavor_test:TestLinuxPlatformFlavor_GetPcrDetails() failed to unmarshall tagcertificate : ", err)
	}

	testPcrList := make(map[hvs.PCR]hvs.PcrListRules)
	testPcrList[hvs.PCR{Index: 17, Bank: "SHA256"}] = hvs.PcrListRules{
		PcrMatches: true,
		PcrEquals: hvs.PcrEquals{
			IsPcrEquals:   false,
			ExcludingTags: map[string]bool{"LCP_CONTROL_HASH": true, "initrd": true},
		},
	}

	testPcrList[hvs.PCR{Index: 18, Bank: "SHA256"}] = hvs.PcrListRules{
		PcrMatches: true,
		PcrEquals: hvs.PcrEquals{
			IsPcrEquals: false,
		},
		PcrIncludes: map[string]bool{"LCP_CONTROL_HASH": true},
	}

	type fields struct {
		HostManifest    *hcTypes.HostManifest
		HostInfo        *taModel.HostInfo
		TagCertificate  *cm.X509AttributeCertificate
		FlavorTemplates []hvs.FlavorTemplate
	}
	type args struct {
		pcrManifest     hcTypes.PcrManifest
		pcrList         map[hvs.PCR]hvs.PcrListRules
		includeEventLog bool
	}

	testFields := fields{
		HostManifest:    hm,
		HostInfo:        &hm.HostInfo,
		TagCertificate:  tagCert,
		FlavorTemplates: getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath),
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []hcTypes.PCRS
		wantErr bool
	}{
		{
			name:   "valid case1",
			fields: testFields,
			args: args{
				pcrManifest:     hm.PcrManifest,
				pcrList:         testPcrList,
				includeEventLog: true,
			},
		},
		{
			name:   "valid case2",
			fields: testFields,
			args: args{
				pcrManifest:     hm.PcrManifest,
				pcrList:         testPcrList,
				includeEventLog: false,
			},
		},
	}
	for _, tt := range tests {
		var got []hcTypes.PCRS
		t.Run(tt.name, func(t *testing.T) {
			rhelpf := LinuxPlatformFlavor{
				HostManifest:    tt.fields.HostManifest,
				HostInfo:        tt.fields.HostInfo,
				TagCertificate:  tt.fields.TagCertificate,
				FlavorTemplates: tt.fields.FlavorTemplates,
			}
			if got = rhelpf.GetPcrDetails(tt.args.pcrManifest, tt.args.pcrList, tt.args.includeEventLog); len(got) == 0 {
				t.Errorf("LinuxPlatformFlavor.GetPcrDetails() unable to perform GetPcrDetails")
			}
		})
	}
}
