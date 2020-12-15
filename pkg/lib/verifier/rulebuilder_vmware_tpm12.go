/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "vmware" vendor and TPM 1.2
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type ruleBuilderVMWare12 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *types.HostManifest
	signedFlavor         *hvs.SignedFlavor
	rules                []rules.Rule
}

func newRuleBuilderVMWare12(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor) (ruleBuilder, error) {
	builder := ruleBuilderVMWare12{
		verifierCertificates: verifierCertificates,
		hostManifest:         hostManifest,
		signedFlavor:         signedFlavor,
	}

	return &builder, nil
}

func (builder *ruleBuilderVMWare12) GetName() string {
	return "VMware Host Trust Policy"
}

//TODO : Need to add pcr/event log rule with the existing structure for all flavors in esxi flow.

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// TagCertificateTrusted
// PcrMatchesConstant rule for PCR 22
func (builder *ruleBuilderVMWare12) GetAssetTagRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// TagCertificateTrusted
	//
	tagCertificateTrusted, err := getTagCertificateTrustedRule(builder.verifierCertificates.AssetTagCACertificates, &builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}

	results = append(results, tagCertificateTrusted)
	//TODO Have to handle the commented out code while doing Esxi
	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 0, 17
func (builder *ruleBuilderVMWare12) GetPlatformRules() ([]rules.Rule, error) {
	//TODO Have to handle the commented out code while doing Esxi
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 18, 20
// PcrEventLogEqualsExcluding rule for PCR 19 (excludes dynamic modules based on component name)
// PcrEventLogIntegrity rule for PCR 19
func (builder *ruleBuilderVMWare12) GetOsRules() ([]rules.Rule, error) {
	//TODO Have to handle the commented out code while doing Esxi
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrEventLogIncludes rule for PCR 19
// PcrEventLogIntegrity rule for PCR 19
func (builder *ruleBuilderVMWare12) GetHostUniqueRules() ([]rules.Rule, error) {
	//TODO Have to handle the commented out code while doing Esxi
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare12) GetSoftwareRules() ([]rules.Rule, error) {
	return nil, nil
}
