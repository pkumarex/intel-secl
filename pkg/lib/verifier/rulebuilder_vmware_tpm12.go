/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "vmware" vendor and TPM 1.2
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
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

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcr22 := []types.PcrIndex{types.PCR22}

	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcr22, &builder.signedFlavor.Flavor, common.FlavorPartAssetTag)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrMatchesContantsRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 0, 17
func (builder *ruleBuilderVMWare12) GetPlatformRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcr0and17 := []types.PcrIndex{types.PCR0, types.PCR17}

	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcr0and17, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrMatchesContantsRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 18, 20
// PcrEventLogEqualsExcluding rule for PCR 19 (excludes dynamic modules based on component name)
// PcrEventLogIntegrity rule for PCR 19
func (builder *ruleBuilderVMWare12) GetOsRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcrs18and20 := []types.PcrIndex{types.PCR18, types.PCR20}

	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcrs18and20, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrMatchesContantsRules...)

	//
	// Add 'PcrEventLogEqualsExcluding' rules...
	//
	pcr19 := []types.PcrIndex{types.PCR19}
	pcrEventLogEqualsExcludingRules, err := getPcrEventLogEqualsExcludingRules(pcr19, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogEqualsExcludingRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr19, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIntegrityRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrEventLogIncludes rule for PCR 19
// PcrEventLogIntegrity rule for PCR 19
func (builder *ruleBuilderVMWare12) GetHostUniqueRules() ([]rules.Rule, error) {

	var results []rules.Rule
	pcr19 := []types.PcrIndex{types.PCR19}

	//
	// Add 'PcrEventLogIncludes' rules...
	//
	pcrEventLogIncludesRules, err := getPcrEventLogIncludesRules(pcr19, &builder.signedFlavor.Flavor, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIncludesRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr19, &builder.signedFlavor.Flavor, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIntegrityRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare12) GetSoftwareRules() ([]rules.Rule, error) {
	return nil, nil
}
