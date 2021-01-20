/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"

	"github.com/google/uuid"
	asset_tag "github.com/intel-secl/intel-secl/v3/pkg/lib/asset-tag"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

//getPcrMatchesConstantRules method will create PcrMatchesConstantRule and return the rule
//return nil if error occurs
func getPcrMatchesConstantRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, pcrLogData *types.PCRS, marker common.FlavorPart) ([]rules.Rule, error) {
	var pcrRules []rules.Rule
	var rule rules.Rule
	var err error

	if pcrLogData != nil {
		rule, err = rules.NewPcrMatchesConstant(nil, pcrLogData, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrMatchesConstant rule ")
		}
	} else {
		// iterate over the banks, collecting the values for each supplied index
		// and create PcrMatchesConstant rules.
		for bank, pcrMap := range flavor.Pcrs {
			for _, index := range pcrs {
				if expectedPcrEx, ok := pcrMap[index.String()]; ok {
					expectedPcr, _ := rules.FlavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)

					rule, err := rules.NewPcrMatchesConstant(expectedPcr, nil, marker)
					if err != nil {
						return nil, errors.Wrapf(err, "An error occurred creating a PcrMatchesConstant rule for bank '%s', index '%s'", bank, index)
					}

					pcrRules = append(pcrRules, rule)
				}
			}
		}
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getPcrEventLogEqualsRules method will create PcrEventLogEqualsRule and return the rule
//return nil if error occurs
func getPcrEventLogEqualsRules(pcrs []types.PcrIndex, pcrLogData *types.PCRS, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	if pcrLogData != nil {
		expectedPcrEventLogEntry := types.TpmEventLog{
			Pcr: types.PCR{
				Index: pcrLogData.PCR.Index,
				Bank:  pcrLogData.PCR.Bank,
			},
			TpmEvent: pcrLogData.EventlogEqual.Events,
		}

		rule, err := rules.NewPcrEventLogEquals(nil, &expectedPcrEventLogEntry, uuid.Nil, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEquals rule for bank '%s', index '%d'", pcrLogData.PCR.Bank, pcrLogData.PCR.Index)
		}
		pcrRules = append(pcrRules, rule)

	} else {
		// iterate over the banks, collecting the values for each supplied index
		// and create PcrEventLogEquals rules (when present).
		for bank, pcrMap := range flavor.Pcrs {
			for _, index := range pcrs {
				if expectedPcrEx, ok := pcrMap[index.String()]; ok {

					expectedEventLogEntry := types.EventLogEntry{
						PcrIndex:  index,
						PcrBank:   types.SHAAlgorithm(bank),
						EventLogs: expectedPcrEx.Event,
					}

					rule, err := rules.NewPcrEventLogEquals(&expectedEventLogEntry, nil, flavor.Meta.ID, marker)
					if err != nil {
						return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
					}

					pcrRules = append(pcrRules, rule)
				}
			}
		}
	}

	return pcrRules, nil
}

//getPcrEventLogEqualsExcludingRules method will create PcrEventLogEqualsRule and return the rule
//return nil if error occurs
func getPcrEventLogEqualsExcludingRules(pcrs []types.PcrIndex, pcrLogData *types.PCRS, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	if pcrLogData != nil {
		expectedPcrEventLogEntry := types.TpmEventLog{
			Pcr: types.PCR{
				Index: pcrLogData.PCR.Index,
				Bank:  pcrLogData.PCR.Bank,
			},
			TpmEvent: pcrLogData.EventlogEqual.Events,
		}
		rule, err := rules.NewPcrEventLogEqualsExcluding(nil, &expectedPcrEventLogEntry, nil, pcrLogData.EventlogEqual.ExcludeTags, uuid.Nil, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%d'", pcrLogData.PCR.Bank, pcrLogData.PCR.Index)
		}
		pcrRules = append(pcrRules, rule)
	} else {

		// iterate over the banks, collecting the values for each supplied index
		// and create PcrEventLogEqualsExcluding rules (when present).
		for bank, pcrMap := range flavor.Pcrs {
			for _, index := range pcrs {
				if expectedPcrEx, ok := pcrMap[index.String()]; ok {

					expectedEventLogEntry := types.EventLogEntry{
						PcrIndex:  index,
						PcrBank:   types.SHAAlgorithm(bank),
						EventLogs: expectedPcrEx.Event,
					}
					expectedPcr, _ := rules.FlavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)
					rule, err := rules.NewPcrEventLogEqualsExcluding(&expectedEventLogEntry, nil, expectedPcr, nil, flavor.Meta.ID, marker)
					if err != nil {
						return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
					}

					pcrRules = append(pcrRules, rule)
				}
			}
		}
	}

	return pcrRules, nil
}

//getPcrEventLogIntegrityRules method will create PcrEventLogIntegrityRule and return the rule
//return nil if error occurs
func getPcrEventLogIntegrityRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, pcrLogData *types.PCRS, marker common.FlavorPart) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	if pcrLogData != nil {
		rule, err := rules.NewPcrEventLogIntegrity(pcrLogData, nil, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIntegrity rule for bank '%s', index '%d'", pcrLogData.PCR.Bank, pcrLogData.PCR.Index)
		}
		pcrRules = append(pcrRules, rule)
	} else {
		// iterate over the banks, collecting the values for each supplied index
		// and create PcrEventLogIntegrity rules (when present).
		for bank, pcrMap := range flavor.Pcrs {
			for _, index := range pcrs {
				if expectedPcrEx, ok := pcrMap[index.String()]; ok {
					expectedPcr, _ := rules.FlavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)

					rule, err := rules.NewPcrEventLogIntegrity(nil, expectedPcr, marker)
					if err != nil {
						return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIntegrity rule for bank '%s', index '%s'", bank, index)
					}
					pcrRules = append(pcrRules, rule)
				}
			}
		}
	}

	return pcrRules, nil
}

//getAssetTagMatchesRule method will create AssetTagMatchesRule and return the rule
//return nil if error occurs
func getAssetTagMatchesRule(flavor *hvs.Flavor) (rules.Rule, error) {
	var rule rules.Rule
	var err error

	// if the flavor has a valid asset tag certificate, add the AssetTagMatches rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	// Load "tags" from the asset tag certificate
	assetTagCertficate, err := x509.ParseCertificate(flavor.External.AssetTag.TagCertificate.Encoded)
	if err != nil {
		return nil, errors.Wrap(err, "Could not parse asset tag certificate")
	}

	tags := make([]asset_tag.TagKvAttribute, 0)
	for _, extensions := range assetTagCertficate.Extensions {
		var tagAttribute asset_tag.TagKvAttribute
		_, err = asn1.Unmarshal(extensions.Value, &tagAttribute)
		if err != nil {
			return nil, errors.Wrap(err, "Error parsing asset tag attribute")
		}
		tags = append(tags, tagAttribute)
	}

	hash := sha512.New384()
	_, err = hash.Write(flavor.External.AssetTag.TagCertificate.Encoded)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to write encoded tag certificate")
	}

	expectedAssetTagDigest := hash.Sum(nil)
	// now create the asset tag matches rule...
	rule, err = rules.NewAssetTagMatches(expectedAssetTagDigest, tags)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create the new AssetTagMatches rule")
	}

	return rule, nil
}

//getTagCertificateTrustedRule method will create TagCertificateTrustedRule and return the rule
//return nil if error occurs
func getTagCertificateTrustedRule(assetTagCACertificates *x509.CertPool, flavor *hvs.Flavor) (rules.Rule, error) {
	var rule rules.Rule
	var err error

	// if the flavor has a valid asset tag certificate, add the TagCertificateTrusted rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	rule, err = rules.NewTagCertificateTrusted(assetTagCACertificates, &flavor.External.AssetTag.TagCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create the TagCertificateTrusted rule")
	}

	return rule, nil
}

//getPcrEventLogIncludesRules method will create PcrEventLogIncludesRule and return the rule
//return nil if error occurs
func getPcrEventLogIncludesRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, pcrLogData *types.PCRS, marker common.FlavorPart) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	if pcrLogData != nil {
		expectedPcrEventLogEntry := types.TpmEventLog{
			Pcr: types.PCR{
				Index: pcrLogData.PCR.Index,
				Bank:  pcrLogData.PCR.Bank,
			},
			TpmEvent: pcrLogData.EventlogIncludes,
		}

		rule, err := rules.NewPcrEventLogIncludes(nil, &expectedPcrEventLogEntry, nil, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIncludes rule for bank '%s', index '%d'", pcrLogData.PCR.Bank, pcrLogData.PCR.Index)
		}
		pcrRules = append(pcrRules, rule)
	} else {
		for bank, pcrMap := range flavor.Pcrs {
			for _, index := range pcrs {
				if expectedPcrEx, ok := pcrMap[index.String()]; ok {

					expectedEventLogEntry := types.EventLogEntry{
						PcrIndex:  index,
						PcrBank:   types.SHAAlgorithm(bank),
						EventLogs: expectedPcrEx.Event,
					}

					expectedPcr, _ := rules.FlavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)
					rule, err := rules.NewPcrEventLogIncludes(&expectedEventLogEntry, nil, expectedPcr, marker)
					if err != nil {
						return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
					}
					pcrRules = append(pcrRules, rule)
				}
			}
		}
	}

	return pcrRules, nil
}
