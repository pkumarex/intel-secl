/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"reflect"

	asset_tag "github.com/intel-secl/intel-secl/v3/pkg/lib/asset-tag"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

//getPcrMatchesConstantRules method will create PcrMatchesConstantRule and return the rule
//return nil if error occurs
func getPcrMatchesConstantRules(pcrData *model.NewFVPcrEx, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	rule, err := rules.NewFVPcrMatchesConstant(pcrData, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a PcrMatchesConstant rule ")
	}

	results = append(results, rule)

	return results, nil
}

//getPcrEventLogEqualsRules method will create PcrEventLogEqualsRule and return the rule
//return nil if error occurs
func getPcrEventLogEqualsRules(pcrData *model.NewFVPcrEx, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	if !reflect.ValueOf(pcrData).IsZero() {

		expectedEventLogEntry := types.NewFVEventLogEntry{
			NewPCR: types.NewPcr{
				PcrIndex: pcrData.PCR.Index,
				PcrBank:  types.SHAAlgorithm(pcrData.PCR.Bank),
			},
			EventLogs:   pcrData.EventlogEqual.Events,
			ExcludeTags: pcrData.EventlogEqual.ExcludeTags,
		}

		if len(pcrData.EventlogEqual.ExcludeTags) == 0 {
			rule, err := rules.NewPcrEventLogEquals(&expectedEventLogEntry, marker)
			if err != nil {
				return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEquals rule for bank '%s', index '%d'", pcrData.PCR.Bank, pcrData.PCR.Index)
			}
			results = append(results, rule)
		} else {
			rule, err := rules.NewPcrEventLogEqualsExcluding(&expectedEventLogEntry, pcrData, pcrData.EventlogEqual.ExcludeTags, marker)
			if err != nil {
				return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%d'", pcrData.PCR.Bank, pcrData.PCR.Index)
			}
			results = append(results, rule)
		}

	}

	return results, nil
}

//getPcrEventLogIntegrityRules method will create PcrEventLogIntegrityRule and return the rule
//return nil if error occurs
func getPcrEventLogIntegrityRules(pcrData *model.NewFVPcrEx, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrEventLogIntegrity rules (when present).

	if !reflect.ValueOf(pcrData).IsZero() {
		rule, err := rules.NewPcrEventLogIntegrity(pcrData, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIntegrity rule for bank '%s', index '%d'", pcrData.PCR.Bank, pcrData.PCR.Index)
		}

		results = append(results, rule)
	}

	return results, nil
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
	hash.Write(flavor.External.AssetTag.TagCertificate.Encoded)
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
func getPcrEventLogIncludesRules(pcrData *model.NewFVPcrEx, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	if !reflect.ValueOf(pcrData).IsZero() {

		expectedEventLogEntry := types.NewFVEventLogEntry{
			NewPCR: types.NewPcr{
				PcrIndex: pcrData.PCR.Index,
				PcrBank:  types.SHAAlgorithm(pcrData.PCR.Bank),
			},
			EventLogs: pcrData.EventlogIncludes,
		}

		rule, err := rules.NewPcrEventLogIncludes(&expectedEventLogEntry, marker)
		if err != nil {
			return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIncludes rule for bank '%s', index '%d'", pcrData.PCR.Bank, pcrData.PCR.Index)
		}

		results = append(results, rule)
	}

	return results, nil
}
