/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"reflect"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	flavormodel "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

// A ruleBuilder creates flavor specific rules for a particular
// vendor (ex. intel TPM2.0 vs. vmware TPM1.2 vs. vmware TPM2.0)
type ruleBuilder interface {
	GetAssetTagRules() ([]rules.Rule, error)
	GetPlatformRules() ([]rules.Rule, error)
	GetOsRules() ([]rules.Rule, error)
	GetHostUniqueRules() ([]rules.Rule, error)
	GetSoftwareRules() ([]rules.Rule, error)
	GetName() string
}

// The ruleFactory uses flavor and manifest data to determine
// which vendor specific rule builder to use when creating rules
// in 'GetVerificationRules'.
type ruleFactory struct {
	verifierCertificates         VerifierCertificates
	hostManifest                 *types.HostManifest
	signedFlavor                 *hvs.SignedFlavor
	skipSignedFlavorVerification bool
}

func NewRuleFactory(verifierCertificates VerifierCertificates,
	hostManifest *types.HostManifest,
	signedFlavor *hvs.SignedFlavor,
	skipSignedFlavorVerification bool) *ruleFactory {

	return &ruleFactory{
		verifierCertificates:         verifierCertificates,
		hostManifest:                 hostManifest,
		signedFlavor:                 signedFlavor,
		skipSignedFlavorVerification: skipSignedFlavorVerification,
	}
}

//GetVerificationRules method is used to get the verification rules dynamically for pcr/event log rules
//Other rules like aik certificate,asset tag rules will be hardcoded based on vendor and flavor part
func (factory *ruleFactory) GetVerificationRules() ([]rules.Rule, string, error) {

	var flavorPart common.FlavorPart
	var requiredRules, pcrRule []rules.Rule

	ruleBuilder, err := factory.getRuleBuilder()
	if err != nil {
		return nil, "", errors.Wrap(err, "Could not retrieve rule builder")
	}

	err = (&flavorPart).Parse(factory.signedFlavor.Flavor.Meta.Description[flavormodel.FlavorPart].(string))
	if err != nil {
		return nil, "", errors.Wrap(err, "Could not retrieve flavor part name")
	}

	switch flavorPart {
	case common.FlavorPartPlatform:
		requiredRules, err = ruleBuilder.GetPlatformRules()
	case common.FlavorPartAssetTag:
		requiredRules, err = ruleBuilder.GetAssetTagRules()
	case common.FlavorPartOs:
		requiredRules, err = ruleBuilder.GetOsRules()
	case common.FlavorPartHostUnique:
		requiredRules, err = ruleBuilder.GetHostUniqueRules()
	case common.FlavorPartSoftware:
		requiredRules, err = ruleBuilder.GetSoftwareRules()
	default:
		return nil, "", errors.Errorf("Cannot build requiredRules for unknown flavor part %s", flavorPart)

	}

	if ruleBuilder.GetName() == "Intel Host Trust Policy" {
		flavorPcrs := factory.signedFlavor.Flavor.PcrLogs

		// Iterate the pcrs section to get rules
		for _, rule := range flavorPcrs {

			eventsPresent := false
			integrityRuleAdded := false
			value := reflect.Indirect(reflect.ValueOf(rule))

			for i := 0; i < value.NumField(); i++ {

				if value.Type().Field(i).Name == "EventlogEqual" && rule.EventlogEqual != nil {
					eventsPresent = true
					//call method to create pcr event log equals rule
					if len(rule.EventlogEqual.ExcludeTags) == 0 {
						pcrRule, err = getPcrEventLogEqualsRules(nil, &rule, nil, flavorPart)
					} else {
						pcrRule, err = getPcrEventLogEqualsExcludingRules(nil, &rule, nil, flavorPart)
					}
					requiredRules = append(requiredRules, pcrRule...)
				} else if value.Type().Field(i).Name == "EventlogIncludes" && len(rule.EventlogIncludes) > 0 {
					eventsPresent = true
					//call method to create pcr event log includes rule
					pcrRule, err = getPcrEventLogIncludesRules(nil, nil, &rule, flavorPart)
					requiredRules = append(requiredRules, pcrRule...)
				} else if value.Type().Field(i).Name == "PCRMatches" && rule.PCRMatches {
					//call method to create pcr matches constant rule
					pcrRule, err = getPcrMatchesConstantRules(nil, nil, &rule, flavorPart)
					requiredRules = append(requiredRules, pcrRule...)
				}

				if eventsPresent == true && integrityRuleAdded == false {
					//add Integrity rules//
					integrityRuleAdded = true
					pcrRule, err = getPcrEventLogIntegrityRules(nil, nil, &rule, flavorPart)
					requiredRules = append(requiredRules, pcrRule...)
				}
				if err != nil {
					return nil, "", errors.Wrapf(err, "Error creating trust requiredRules for flavor '%s'", factory.signedFlavor.Flavor.Meta.ID)
				}

			}

		}
	}

	// if skip flavor signing verification is enabled, add the FlavorTrusted.
	if !factory.skipSignedFlavorVerification {

		var flavorPart common.FlavorPart
		err := (&flavorPart).Parse(factory.signedFlavor.Flavor.Meta.Description[flavormodel.FlavorPart].(string))
		if err != nil {
			return nil, "", errors.Wrap(err, "Could not retrieve flavor part name")
		}

		flavorTrusted, err := rules.NewFlavorTrusted(factory.signedFlavor,
			factory.verifierCertificates.FlavorSigningCertificate,
			factory.verifierCertificates.FlavorCACertificates,
			flavorPart)

		if err != nil {
			return nil, "", errors.Wrap(err, "Error creating the flavor trusted rule")
		}

		requiredRules = append(requiredRules, flavorTrusted)
	}

	return requiredRules, ruleBuilder.GetName(), nil

}

//getRuleBuilder method will get the ruler builder based on vendor
func (factory *ruleFactory) getRuleBuilder() (ruleBuilder, error) {

	var builder ruleBuilder
	var vendor constants.Vendor
	var err error

	vendor = factory.signedFlavor.Flavor.Meta.Vendor
	if vendor == constants.VendorUnknown {
		// if for some reason the vendor wasn't provided in the flavor,
		// get the osname from the manifest
		err = (&vendor).GetVendorFromOSName(factory.hostManifest.HostInfo.OSName)
		if err != nil {
			return nil, errors.Wrap(err, "The verifier could not determine the vendor")
		}
	}

	switch vendor {
	case constants.VendorIntel:
		builder, err = newRuleBuilderIntelTpm20(factory.verifierCertificates, factory.hostManifest, factory.signedFlavor)
		if err != nil {
			return nil, errors.Wrap(err, "There was an error creating the Intel rule builder")
		}
	case constants.VendorVMware:
		tpmVersionString := factory.signedFlavor.Flavor.Meta.Description[flavormodel.TpmVersion].(string)
		if len(tpmVersionString) == 0 {
			tpmVersionString = factory.hostManifest.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion
		}

		if tpmVersionString == "1.2" {
			builder, err = newRuleBuilderVMWare12(factory.verifierCertificates, factory.hostManifest, factory.signedFlavor)
			if err != nil {
				return nil, errors.Wrap(err, "There was an error creating the VMWare 1.2 verification rule builder")
			}
		} else if tpmVersionString == "2.0" {
			builder, err = newRuleBuilderVMWare20(factory.verifierCertificates, factory.hostManifest, factory.signedFlavor)
			if err != nil {
				return nil, errors.Wrap(err, "There was an error creating the VMWare 1.2 verification rule builder")
			}
		} else {
			return nil, errors.Errorf("Unknown TPM version '%s'", tpmVersionString)
		}

	default:
		return nil, errors.Errorf("Vendor '%s' is not currently supported", string(vendor))
	}

	return builder, nil
}
