/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "intel" vendor and TPM 2.0.
//

import (
	"reflect"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	flavormodel "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

type ruleBuilderIntelTpm20 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *types.HostManifest
	signedFlavor         *hvs.SignedFlavor
	rules                []rules.Rule
}

func newRuleBuilderIntelTpm20(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor) (ruleBuilder, error) {
	builder := ruleBuilderIntelTpm20{
		verifierCertificates: verifierCertificates,
		hostManifest:         hostManifest,
		signedFlavor:         signedFlavor,
	}

	return &builder, nil
}

func (builder *ruleBuilderIntelTpm20) GetName() string {
	return "Intel Host Trust Policy"
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted
// PcrMatchesConstant depend on HW features present in flavor
// PcrEventLogEqualsExcluding rule for PCR 17, 18
// PcrEventLogIntegrity rule for PCR 17,18 (if tboot is installed)
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetPlatformRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'AikCertificateTrusted' rule...
	//
	aikCertificateTrusted, err := rules.NewAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, aikCertificateTrusted)

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcrs, err := builder.getPlatformPcrsFromHardwareMeta()
	if err != nil {
		return nil, err
	}

	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcrs, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrMatchesContantsRules...)

	//
	// Add 'PcrEventLogEqualsExcluding' rules...
	//
	pcrs = []types.PcrIndex{types.PCR17, types.PCR18}
	pcrEventLogEqualsExcludingRules, err := getPcrEventLogEqualsExcludingRules(pcrs, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogEqualsExcludingRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	tbootInstalled := builder.signedFlavor.Flavor.Meta.Description[flavormodel.TbootInstalled]
	if tbootInstalled != nil {
		pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcrs, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
		if err != nil {
			return nil, err
		}

		results = append(results, pcrEventLogIntegrityRules...)
	}

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// TagCertificateTrusted
// AssetTagMatches
// FlavorTrusted
func (builder *ruleBuilderIntelTpm20) GetAssetTagRules() ([]rules.Rule, error) {

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
// AikCertificateTrusted
// PcrEventLogIntegrity rule for PCR 17 (if tboot is installed)
// PcrEventLogIncludes rule for PCR 17
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetOsRules() ([]rules.Rule, error) {

	var results []rules.Rule
	pcr17 := []types.PcrIndex{types.PCR17}

	//
	// Add 'AikCertificateTrusted' rule...
	//
	aikCertificateTrusted, err := rules.NewAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, aikCertificateTrusted)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	tbootInstalled := builder.signedFlavor.Flavor.Meta.Description[flavormodel.TbootInstalled]
	if tbootInstalled != nil {
		pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr17, &builder.signedFlavor.Flavor, common.FlavorPartOs)
		if err != nil {
			return nil, err
		}

		results = append(results, pcrEventLogIntegrityRules...)
	}

	//
	// Add 'PcrEventLogIncludes' rules...
	//
	pcrEventLogIncludesRules, err := getPcrEventLogIncludesRules(pcr17, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIncludesRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted
// PcrEventLogIncludes rule for PCR 17, 18
// PcrEventLogIntegrity rule for PCR 17, 18 (if tboot is installed)
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetHostUniqueRules() ([]rules.Rule, error) {

	var results []rules.Rule
	pcr17and18 := []types.PcrIndex{types.PCR17, types.PCR18}

	//
	// Add 'AikCertificateTrusted' rule...
	//
	aikCertificateTrusted, err := rules.NewAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	results = append(results, aikCertificateTrusted)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	tbootInstalled := builder.signedFlavor.Flavor.Meta.Description[flavormodel.TbootInstalled]
	if tbootInstalled != nil {
		pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr17and18, &builder.signedFlavor.Flavor, common.FlavorPartHostUnique)
		if err != nil {
			return nil, err
		}

		results = append(results, pcrEventLogIntegrityRules...)
	}

	//
	// Add 'PcrEventLogIncludes' rules...
	//
	pcrEventLogIncludesRules, err := getPcrEventLogIncludesRules(pcr17and18, &builder.signedFlavor.Flavor, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIncludesRules...)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// XmlMeasurementsDigestEquals
// PcrEventLogIntegrity rule for PCR 15
// XmlMeasurementLogIntegrity
// XmlMeasurementLogEquals
// FlavorTrusted (added in verifierimpl)
func (builder *ruleBuilderIntelTpm20) GetSoftwareRules() ([]rules.Rule, error) {

	var results []rules.Rule

	//
	// Add 'XmlEventLogDigestEquals' rule...
	//
	meta := builder.signedFlavor.Flavor.Meta
	if reflect.DeepEqual(meta, flavormodel.Meta{}) {
		return nil, errors.New("'Meta' was not present in the flavor")
	}

	//To-Do add comparsion for maps
	// if reflect.DeepEqual(meta.Description, flavormodel.Description{}) {
	// 	return nil, errors.New("'Description' was not present in the flavor")
	// }

	xmlMeasurementLogDigestEqualsRule, err := rules.NewXmlMeasurementLogDigestEquals(meta.Description[flavormodel.DigestAlgorithm].(string), meta.ID)
	if err != nil {
		return nil, err
	}

	results = append(results, xmlMeasurementLogDigestEqualsRule)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//
	pcr15 := []types.PcrIndex{types.PCR15}
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr15, &builder.signedFlavor.Flavor, common.FlavorPartSoftware)
	if err != nil {
		return nil, err
	}

	results = append(results, pcrEventLogIntegrityRules...)

	//
	// Add 'XmlMeasurementLogIntegrity' rule...
	//
	if builder.signedFlavor.Flavor.Software == nil {
		return nil, errors.New("'Software' was not present in the flavor")
	}

	xmlMeasurementLogIntegrityRule, err := rules.NewXmlMeasurementLogIntegrity(meta.ID, meta.Description[flavormodel.Label].(string), builder.signedFlavor.Flavor.Software.CumulativeHash)
	results = append(results, xmlMeasurementLogIntegrityRule)

	//
	// Add 'XmlMeasurementLogEquals' rule...
	//
	var measurements []ta.FlavorMeasurement
	for _, measurement := range builder.signedFlavor.Flavor.Software.Measurements {
		measurements = append(measurements, measurement)
	}

	xmlMeasurementLogEqualsRule, err := rules.NewXmlMeasurementLogEquals(&builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}

	results = append(results, xmlMeasurementLogEqualsRule)

	return results, nil
}

// Based on the manifest's hardware metadata, return the correct PCRs...
//   - Always match on PCR0
//   - If CBNT is enabled and profile 5: Add PCR7
//   - If SUEFI is enabled: add PCR0-PCR7
func (builder *ruleBuilderIntelTpm20) getPlatformPcrsFromHardwareMeta() ([]types.PcrIndex, error) {

	var feature *flavormodel.Feature
	var pcrs []types.PcrIndex

	pcrs = append(pcrs, types.PCR0)

	if builder.signedFlavor.Flavor.Hardware == nil {
		return nil, errors.New("The flavor's Hardware information is not present")
	}

	feature = builder.signedFlavor.Flavor.Hardware.Feature
	if feature == nil {
		return nil, errors.New("The flavor's Feature information is not present")
	}

	if feature.CBNT != nil {
		if feature.CBNT.Enabled {
			if feature.CBNT.Profile == "BTGP5" {
				pcrs = append(pcrs, types.PCR7)
			}
		}
	}

	if feature.UEFI != nil && feature.UEFI.SecureBootEnabled {
		suefiPcrs := []types.PcrIndex{
			types.PCR1,
			types.PCR2,
			types.PCR3,
			types.PCR4,
			types.PCR5,
			types.PCR6,
			types.PCR7,
		}
		pcrs = append(pcrs, suefiPcrs...)
	}

	return pcrs, nil
}
