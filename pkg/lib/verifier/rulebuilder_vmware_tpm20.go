/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "vmware" vendor and TPM 2.0
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
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

	var results []rules.Rule

	pcrs17and18 := []types.PcrIndex{types.PCR17, types.PCR18}
	pcrsZero17and18 := append(pcrs17and18, types.PCR0)

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcrsZero17and18, &builder.signedFlavor.Flavor, nil, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrMatchesContantsRules...)

	//
	// Add 'PcrEventLogEquals' rules...
	//
	pcrEventLogEqualsRules, err := getPcrEventLogEqualsRules(pcrs17and18, nil, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogEqualsRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcrs17and18, &builder.signedFlavor.Flavor, nil, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIntegrityRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrMatchesConstant rule for PCR 19
// PcrEventLogEquals rule for PCR 19
// PcrEventLogIntegrity rule for PCR 19, 20, 21
// PcrEventLogEqualsExcluding rule for PCR 20,21
func (builder *ruleBuilderVMWare20) GetOsRules() ([]rules.Rule, error) {

	var results []rules.Rule

	pcr19 := []types.PcrIndex{types.PCR19}
	pcrs20and21 := []types.PcrIndex{types.PCR20, types.PCR21}
	pcrs19thru21 := append(pcr19, pcrs20and21...)

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcr19, &builder.signedFlavor.Flavor, nil, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrMatchesContantsRules...)

	//
	// Add 'PcrEventLogEquals' rules...
	//
	pcrEventLogEqualsRules, err := getPcrEventLogEqualsRules(pcr19, nil, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogEqualsRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcrs19thru21, &builder.signedFlavor.Flavor, nil, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIntegrityRules...)

	//
	// Add 'PcrEventLogEqualsExcluding' rules...
	//
	pcrEventLogEqualsExcludingRules, err := getPcrEventLogEqualsExcludingRules(pcrs20and21, nil, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogEqualsExcludingRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// PcrEventLogIncludes rule for PCR 20,21
// PcrEventLogIntegrity rule for PCR 20,21
func (builder *ruleBuilderVMWare20) GetHostUniqueRules() ([]rules.Rule, error) {

	var results []rules.Rule
	pcrs20and21 := []types.PcrIndex{types.PCR20, types.PCR21}

	//
	// Add 'PcrEventLogIncludes' rules...
	//
	pcrEventLogIncludesRules, err := getPcrEventLogIncludesRules(pcrs20and21, &builder.signedFlavor.Flavor, nil, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIncludesRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcrs20and21, &builder.signedFlavor.Flavor, nil, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIntegrityRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare20) GetSoftwareRules() ([]rules.Rule, error) {
	return nil, nil
}
