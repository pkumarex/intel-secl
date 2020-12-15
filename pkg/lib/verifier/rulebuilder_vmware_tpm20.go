/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "vmware" vendor and TPM 2.0
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type ruleBuilderVMWare20 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *types.HostManifest
	signedFlavor         *hvs.SignedFlavor
	rules                []rules.Rule
}

func newRuleBuilderVMWare20(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor) (ruleBuilder, error) {
	builder := ruleBuilderVMWare20{
		verifierCertificates: verifierCertificates,
		hostManifest:         hostManifest,
		signedFlavor:         signedFlavor,
	}

	return &builder, nil
}

func (builder *ruleBuilderVMWare20) GetName() string {
	return "VMware Host Trust Policy"
}

//TODO : Need to add pcr/event log rule with the existing structure for all flavors in esxi flow.

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// TagCertificateTrusted
// AssetTag Matches
func (builder *ruleBuilderVMWare20) GetAssetTagRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// TagCertificateTrusted
	//
	tagCertificateTrusted, err := getTagCertificateTrustedRule(builder.verifierCertificates.AssetTagCACertificates, &builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}

	results = append(results, tagCertificateTrusted)

	//
	// AssetTagMatches
	//
	assetTagMatches, err := getAssetTagMatchesRule(&builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}

	results = append(results, assetTagMatches)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 0, 17, 18
// PcrEventLogEquals for 17,18
// PcrEventLogIntegrity rule for 17,18
func (builder *ruleBuilderVMWare20) GetPlatformRules() ([]rules.Rule, error) {
	//TODO Have to handle the commented out code while doing Esxi
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 19
// PcrEventLogEquals rule for PCR 19
// PcrEventLogIntegrity rule for PCR 19, 20, 21
// PcrEventLogEqualsExcluding rule for PCR 20,21
func (builder *ruleBuilderVMWare20) GetOsRules() ([]rules.Rule, error) {
	//TODO Have to handle the commented out code while doing Esxi
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrEventLogIncludes rule for PCR 20,21
// PcrEventLogIntegrity rule for PCR 20,21
func (builder *ruleBuilderVMWare20) GetHostUniqueRules() ([]rules.Rule, error) {
	//TODO Have to handle the commented out code while doing Esxi
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare20) GetSoftwareRules() ([]rules.Rule, error) {
	return nil, nil
}
