/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/rules"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	flavorVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"reflect"
)

type flvGrpHostTrustReqs struct {
	HostId                          uuid.UUID
	FlavorGroupId                   uuid.UUID
	FlavorMatchPolicies             hvs.FlavorMatchPolicies
	MatchTypeFlavorParts            map[hvs.MatchType][]cf.FlavorPart
	AllOfFlavors                    []hvs.SignedFlavor
	DefinedAndRequiredFlavorTypes   map[cf.FlavorPart]bool
	FlavorPartMatchPolicy           map[cf.FlavorPart]hvs.MatchPolicy
	SkipFlavorSignatureVerification bool
}

func NewFlvGrpHostTrustReqs(hostId uuid.UUID, definedUniqueFlavorParts map[cf.FlavorPart]bool, fg hvs.FlavorGroup, fs domain.FlavorStore, fgs domain.FlavorGroupStore, hostData *types.HostManifest, SkipFlavorSignatureVerification bool) (*flvGrpHostTrustReqs, error) {
	defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Leaving")

	reqs := flvGrpHostTrustReqs{
		HostId:              hostId,
		FlavorGroupId:       fg.ID,
		FlavorMatchPolicies: fg.MatchPolicies,
		//Initialize empty map.
		DefinedAndRequiredFlavorTypes:   make(map[cf.FlavorPart]bool),
		SkipFlavorSignatureVerification: SkipFlavorSignatureVerification,
	}

	var fgRequirePolicyMap map[hvs.FlavorRequiredPolicy][]cf.FlavorPart

	reqs.FlavorPartMatchPolicy, reqs.MatchTypeFlavorParts, fgRequirePolicyMap = fg.GetMatchPolicyMaps()

	if len(reqs.MatchTypeFlavorParts[hvs.MatchTypeAllOf]) > 0 {
		// TODO: this should really be a search on the flavorgroup store which should be able to retrieve a list
		// of flavor ids in the flavorgroup and then call the flavor store with a list of ids. Right now, it only
		// support one flavor id
		var err error
		hostManifestMap, err := getHostManifestMap(hostData, reqs.MatchTypeFlavorParts[hvs.MatchTypeAllOf])
		if err != nil {
			return nil, errors.Wrap(err, "error while creating host manifest map")
		}
		reqs.AllOfFlavors, err = fs.Search(&models.FlavorVerificationFC{
			FlavorFC: models.FlavorFilterCriteria{
				// Flavor Parts of the Search Criteria takes a []cf.FlavorPart - but we have a map.
				// So dump keys of the map into a slice.
				FlavorgroupID: fg.ID,
				FlavorParts:   reqs.MatchTypeFlavorParts[hvs.MatchTypeAllOf],
			},
			FlavorMeta:            hostManifestMap,
			FlavorPartsWithLatest: nil,
		})
		if err != nil {
			return nil, errors.Wrap(err, "error searching flavor for host id "+hostId.String())
		}
		defaultLog.Debugf("%v from Flavorgroup %v Flavors retrieved with ALL_OF policy", fg.ID, len(reqs.AllOfFlavors))
	}

	reqPartsMap := fgRequirePolicyMap[hvs.FlavorRequired]
	reqIfdefPartsMap := fgRequirePolicyMap[hvs.FlavorRequiredIfDefined]

	// create the host defined and required falvorTypes by joining the map
	for _, part := range reqPartsMap {
		reqs.DefinedAndRequiredFlavorTypes[part] = true
	}

	// now add defined if required flavor parts
	flavorPartsInFlavorGroup, err := fgs.GetFlavorTypesInFlavorGroup(fg.ID)
	if err != nil {
		return nil, errors.Wrap(err, "error searching flavor types in flavorgroup ")
	}
	// since the above query returns all the different flavors types in the flavorgroup, filter only
	// those flavor parts that are required if defined
	for _, part := range reqIfdefPartsMap {
		if _, exists := flavorPartsInFlavorGroup[part]; exists {
			reqs.DefinedAndRequiredFlavorTypes[part] = true
		}
	}

	// add the host unique flavor parts
	for part := range definedUniqueFlavorParts {
		if policy, exists := reqs.FlavorPartMatchPolicy[part]; exists &&
			(policy.Required == hvs.FlavorRequiredIfDefined || policy.Required == hvs.FlavorRequired) {
			reqs.DefinedAndRequiredFlavorTypes[part] = true
		}
	}

	return &reqs, nil
}

func (r *flvGrpHostTrustReqs) GetLatestFlavorTypeMap() map[cf.FlavorPart]bool {
	defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Leaving")

	result := make(map[cf.FlavorPart]bool)
	for part := range r.DefinedAndRequiredFlavorTypes {
		if r.FlavorPartMatchPolicy[part].MatchType == hvs.MatchTypeLatest {
			result[part] = true
		} else {
			result[part] = false
		}
	}
	return result
}

func (r *flvGrpHostTrustReqs) MeetsFlavorGroupReqs(trustCache hostTrustCache, verifierCerts flavorVerifier.VerifierCertificates) bool {
	defaultLog.Trace("hosttrust/trust_requirements:MeetsFlavorGroupReqs() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:MeetsFlavorGroupReqs() Leaving")

	if len(trustCache.trustedFlavors) == 0 {
		defaultLog.Debugf("No results found in trust cache for host: %s", r.HostId.String())
		return false
	}

	reqAndDefFlavorTypes := r.DefinedAndRequiredFlavorTypes
	missingRequiredFlavorPartsWithLatest := getMissingRequiredFlavorPartsWithLatest(r.HostId, *r, reqAndDefFlavorTypes, trustCache.trustReport)
	if len(missingRequiredFlavorPartsWithLatest) > 0 {
		defaultLog.Debugf("Host %s has missing required and defined flavor parts: %s", r.HostId.String(), reflect.ValueOf(missingRequiredFlavorPartsWithLatest).MapKeys())
		return false
	}

	ruleAllOfFlavors := rules.NewAllOfFlavors(r.AllOfFlavors, r.getAllOfMarkers(), r.SkipFlavorSignatureVerification, verifierCerts)

	if areAllOfFlavorsMissingInCachedTrustReport(trustCache.trustReport, ruleAllOfFlavors) {
		defaultLog.Debugf("All of flavors exist in policy for host: %s", r.HostId.String())
		defaultLog.Debugf("Some all of flavors do not match what is in the trust cache for host: %s", r.HostId.String())
		return false
	}
	defaultLog.Debugf("Trust cache valid for host: %s", r.HostId.String())
	return true
}

// According to verification-service: RuleAllOfFlavors.java
// the protected 'marker' variable inherited from lib-verifier: BaseRule.java
// does not at all effect the behavior of methods implemented in RuleAllOfFlavors
func (r *flvGrpHostTrustReqs) getAllOfMarkers() []cf.FlavorPart {
	defaultLog.Trace("hosttrust/trust_requirements:getAllOfMarkers() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:getAllOfMarkers() Leaving")
	markers := make([]cf.FlavorPart, 0, len(r.MatchTypeFlavorParts[hvs.MatchTypeAllOf]))
	for _, flavorPart := range r.MatchTypeFlavorParts[hvs.MatchTypeAllOf] {
		markers = append(markers, flavorPart)
	}
	return markers
}
