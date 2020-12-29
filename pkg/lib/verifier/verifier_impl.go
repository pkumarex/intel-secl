/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Implements 'Verifier' interface.
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type verifierImpl struct {
	signedFlavor         *hvs.SignedFlavor
	verifierCertificates VerifierCertificates
	overallTrust         bool
}

//Verify method implements the flavor verification
func (v *verifierImpl) Verify(hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor, skipSignedFlavorVerification bool) (*hvs.TrustReport, error) {

	var err error

	if hostManifest == nil {
		return nil, errors.New("The host manifest cannot be nil")
	}

	if signedFlavor == nil {
		return nil, errors.New("The signed flavor cannot be nil")
	}

	v.signedFlavor = signedFlavor

	// default overall trust to true, change to false during rule evaluation
	v.overallTrust = true

	ruleFactory := NewRuleFactory(v.verifierCertificates, hostManifest, v.signedFlavor, skipSignedFlavorVerification)
	verificationRules, policyName, err := ruleFactory.GetVerificationRules()
	if err != nil {
		return nil, errors.Wrap(err, "Error in getting Verification rules")
	}

	results, err := v.applyRules(verificationRules, hostManifest)
	if err != nil {
		return nil, errors.Wrap(err, "Error in applying Verification rules")
	}

	trustReport := hvs.TrustReport{
		PolicyName:   policyName,
		Results:      results,
		Trusted:      v.overallTrust,
		HostManifest: *hostManifest,
	}

	return &trustReport, nil
}

//applyRules method is used to apply the verifier rules created
func (v *verifierImpl) applyRules(rulesToApply []rules.Rule, hostManifest *types.HostManifest) ([]hvs.RuleResult, error) {

	var results []hvs.RuleResult

	for _, rule := range rulesToApply {

		if rule != nil {
			log.Debugf("Applying verifier rule %T", rule)
			result, err := rule.Apply(hostManifest)

			if err != nil {
				return nil, errors.Wrapf(err, "Error ocrurred applying rule type '%T'", rule)
			}

			// if 'Apply' returned a result with any faults, then the
			// rule is not trusted
			if len(result.Faults) > 0 {
				result.Trusted = false
				v.overallTrust = false
			}

			// assign the flavor id to all rules
			flavorID := v.signedFlavor.Flavor.Meta.ID
			result.FlavorId = &flavorID

			results = append(results, *result)
		}
	}

	return results, nil
}

func (v *verifierImpl) GetVerifierCerts() VerifierCertificates {
	return v.verifierCertificates
}
