/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	flavorVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"sync"
)

var ErrInvalidHostManiFest = errors.New("invalid host data")
var ErrManifestMissingHwUUID = errors.New("host data missing hardware uuid")

type Verifier struct {
	FlavorStore                     domain.FlavorStore
	FlavorGroupStore                domain.FlavorGroupStore
	HostStore                       domain.HostStore
	ReportStore                     domain.ReportStore
	FlavorVerifier                  flavorVerifier.Verifier
	CertsStore                      models.CertificatesStore
	SamlIssuer                      saml.IssuerConfiguration
	SkipFlavorSignatureVerification bool
	hostPCRCache map[uuid.UUID] *types.PcrManifest
	pcrCacheLock        sync.RWMutex

}

func NewVerifier(cfg domain.HostTrustVerifierConfig) domain.HostTrustVerifier {
	return &Verifier{
		FlavorStore:                     cfg.FlavorStore,
		FlavorGroupStore:                cfg.FlavorGroupStore,
		HostStore:                       cfg.HostStore,
		ReportStore:                     cfg.ReportStore,
		FlavorVerifier:                  cfg.FlavorVerifier,
		CertsStore:                      cfg.CertsStore,
		SamlIssuer:                      cfg.SamlIssuerConfig,
		SkipFlavorSignatureVerification: cfg.SkipFlavorSignatureVerification,
	}
}

func (v* Verifier) addHostPCRCache (hostId uuid.UUID, cacheValues *types.PcrManifest){
	v.pcrCacheLock.Lock()
	v.hostPCRCache[hostId] = cacheValues
	v.pcrCacheLock.Unlock()

}
func (v* Verifier) pcrValuesUnChanged (hostId uuid.UUID, hostData *types.HostManifest) bool {
	defaultLog.Info("1. Checking if PCR values are changed")
	v.pcrCacheLock.RLock()
	var cacheValues *types.PcrManifest
	var exists bool
	if cacheValues, exists = v.hostPCRCache[hostId]; !exists {
		v.pcrCacheLock.RUnlock()
		v.addHostPCRCache(hostId,&hostData.PcrManifest)
		return false
	}
	v.pcrCacheLock.RUnlock()

	// compare the values - for the POC, we are only doing SHA256
	var mismatch bool
	for i := 0; i < len(hostData.PcrManifest.Sha256Pcrs); i++ {
		if hostData.PcrManifest.Sha256Pcrs[i].Value != cacheValues.Sha256Pcrs[i].Value {
			mismatch = true
			break
		}
	}
	if mismatch {
		// add the new PCR values to the cache
		v.addHostPCRCache(hostId,&hostData.PcrManifest)
		return false
	}
	defaultLog.Info("2. PCR values are unchanged")
	return true
}

func (v *Verifier) Verify(hostId uuid.UUID, hostData *types.HostManifest, newData bool) (*models.HVSReport, error) {
	defaultLog.Trace("hosttrust/verifier:Verify() Entering")
	defer defaultLog.Trace("hosttrust/verifier:Verify() Leaving")
	if hostData == nil {
		return nil, ErrInvalidHostManiFest
	}
	//TODO: Fix HardwareUUID has to be uuid
	hwUuid, err := uuid.Parse(hostData.HostInfo.HardwareUUID)
	if err != nil || hwUuid == uuid.Nil {
		return nil, ErrManifestMissingHwUUID
	}

	// check if the data has not changed
	if !newData {
		// store data in the cache
		v.addHostPCRCache(hostId, &hostData.PcrManifest)
	} else {
		// check if the PCR Values are unchanged.
		if v.pcrValuesUnChanged(hostId, hostData){
			// retrieve the stored report
			return v.refreshTrustReport(hostId)
		}
	}
	// TODO : remove this when we remove the intermediate collection
	flvGroupIds, err := v.HostStore.SearchFlavorgroups(hostId)
	flvGroups, err := v.FlavorGroupStore.Search(&models.FlavorGroupFilterCriteria{Ids: flvGroupIds})
	if err != nil {
		return nil, errors.New("hosttrust/verifier:Verify() Store access error")
	}
	// start with the presumption that final trust report would be true. It as some point, we get an invalid report,
	// the Overall trust status would be negative
	var finalReportValid = true // This is the final trust report - initialize
	// create an empty trust report with the host manifest
	finalTrustReport := hvs.TrustReport{HostManifest: *hostData}

	// Get the types of host unique flavors (such as HOST_UNIQUE and ASSET_TAG) that exist for the host.
	// This can be used when determining the flavor groups requirement for each flavors.
	// It will reduce the number of calls made to the database to determine this list. Since it applicable for
	// all flavorgroups, repeated calls can be avoided

	hostUniqueFlavorParts, err := v.HostStore.RetrieveDistinctUniqueFlavorParts(hostId)
	if err != nil {
		return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving host unique flavor parts")
	}
	// convert hostUniqueFlavorParts to a map
	hostUniqueFlavorPartsMap := make(map[common.FlavorPart]bool)

	for _, flavorPart := range hostUniqueFlavorParts {
		hostUniqueFlavorPartsMap[common.FlavorPart(flavorPart)] = true
	}

	for _, fg := range flvGroups {
		//TODO - handle errors in case of DB transaction
		fgTrustReqs, err := NewFlvGrpHostTrustReqs(hostId, hostUniqueFlavorPartsMap, fg, v.FlavorStore, v.FlavorGroupStore, hostData, v.SkipFlavorSignatureVerification)
		if err != nil {
			return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving NewFlvGrpHostTrustReqs")
		}
		fgCachedFlavors, err := v.getCachedFlavors(hostId, (fg).ID)
		if err != nil {
			return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving getCachedFlavors")
		}

		var fgTrustCache hostTrustCache
		if len(fgCachedFlavors) > 0 {
			fgTrustCache, err = v.validateCachedFlavors(hostId, hostData, fgCachedFlavors)
			if err != nil {
				return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while validating cache")
			}
		}

		fgTrustReport := fgTrustCache.trustReport
		if !fgTrustReqs.MeetsFlavorGroupReqs(fgTrustCache, v.FlavorVerifier.GetVerifierCerts()) {
			log.Debug("hosttrust/verifier:Verify() Trust cache doesn't meet flavorgroup requirements")
			finalReportValid = false
			fgTrustReport, err = v.CreateFlavorGroupReport(hostId, *fgTrustReqs, hostData, fgTrustCache)
			if err != nil {
				return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while creating flavorgroup report")
			}
		}
		log.Debug("hosttrust/verifier:Verify() Trust status for host id ", hostId, " for flavorgroup ", fg.ID, " is ", fgTrustReport.IsTrusted())
		// append the results
		finalTrustReport.AddResults(fgTrustReport.Results)
	}
	// create a new report if we actually have any results and either the Final Report is untrusted or
	// we have new Data from the host and therefore need to update based on the new report.
	var hvsReport *models.HVSReport
	log.Debugf("hosttrust/verifier:Verify() Final results in report: %d", len(finalTrustReport.Results))
	if len(finalTrustReport.Results) > 0 && (!finalReportValid || newData) {
		log.Debugf("hosttrust/verifier:Verify() Generating new SAML for host: %s", hostId)
		samlReportGen := NewSamlReportGenerator(&v.SamlIssuer)
		samlReport := samlReportGen.GenerateSamlReport(&finalTrustReport)
		finalTrustReport.Trusted = finalTrustReport.IsTrusted()
		log.Debugf("hosttrust/verifier:Verify() Saving new report for host: %s", hostId)
		hvsReport = v.storeTrustReport(hostId, &finalTrustReport, &samlReport)
	}
	return hvsReport, nil
}

func (v *Verifier) getCachedFlavors(hostId uuid.UUID, flavGrpId uuid.UUID) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("hosttrust/verifier:getCachedFlavors() Entering")
	defer defaultLog.Trace("hosttrust/verifier:getCachedFlavors() Leaving")
	// retrieve the IDs of the trusted flavors from the host store
	if flIds, err := v.HostStore.RetrieveTrustCacheFlavors(hostId, flavGrpId); err != nil && len(flIds) == 0 {
		return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving TrustCacheFlavors")
	} else {
		result := make([]hvs.SignedFlavor, 0, len(flIds))
		for _, flvId := range flIds {
			if flv, err := v.FlavorStore.Retrieve(flvId); err == nil {
				result = append(result, *flv)
			}
		}
		return result, nil
	}
}

func (v *Verifier) validateCachedFlavors(hostId uuid.UUID,
	hostData *types.HostManifest,
	cachedFlavors []hvs.SignedFlavor) (hostTrustCache, error) {
	defaultLog.Trace("hosttrust/verifier:validateCachedFlavors() Entering")
	defer defaultLog.Trace("hosttrust/verifier:validateCachedFlavors() Leaving")

	htc := hostTrustCache{
		hostID: hostId,
	}
	var collectiveReport hvs.TrustReport
	var trustCachesToDelete []uuid.UUID
	for _, cachedFlavor := range cachedFlavors {
		//TODO: change the signature verification depending on decision on signed flavors
		report, err := v.FlavorVerifier.Verify(hostData, &cachedFlavor, v.SkipFlavorSignatureVerification)
		if err != nil {
			return hostTrustCache{}, errors.Wrap(err, "hosttrust/verifier:validateCachedFlavors() Error from flavor verifier")
		}
		if report.Trusted {
			htc.trustedFlavors = append(htc.trustedFlavors, cachedFlavor.Flavor)
			collectiveReport.Results = append(collectiveReport.Results, report.Results...)
		} else {
			trustCachesToDelete = append(trustCachesToDelete, cachedFlavor.Flavor.Meta.ID)
		}
	}
	if len(trustCachesToDelete) > 0 {
		// remove cache entries for flavors that could not be verified
		err := v.HostStore.RemoveTrustCacheFlavors(hostId, trustCachesToDelete)
		if err != nil {
			return hostTrustCache{}, errors.Wrap(err, "could not remove trust cache flavors")
		}
	}
	htc.trustReport = collectiveReport
	return htc, nil
}

func (v *Verifier) refreshTrustReport(hostID uuid.UUID) (*models.HVSReport, error) {
	rfc := models.ReportFilterCriteria{
		HostID:        hostID,
		LatestPerHost: true,
	}

	// get the latest trust report from the host and use this to create a new report
	hvsReportCollection, err := v.ReportStore.Search(&rfc)
	if err != nil {
		defaultLog.WithError(err).Warnf("hosttrust/verifier:refreshTrustReport() HVSReport search operation failed")
		return nil, errors.Errorf("HVSReport search operation failed")
	}

	if len(hvsReportCollection) == 0 {
		return nil, errors.Errorf("HVSReport search operation failed")
	}
	log.Debugf("hosttrust/verifier:refreshTrustReport() Generating new SAML for host: %s", hostID)
	log.Info("3. Old report id and expiration time is ", hvsReportCollection[0].HostID, hvsReportCollection[0].Expiration)
	samlReportGen := NewSamlReportGenerator(&v.SamlIssuer)
	samlReport := samlReportGen.GenerateSamlReport(&hvsReportCollection[0].TrustReport)
	//hvsReportCollection[0].TrustReport.Trusted = hvsReportCollection[0].TrustReport.IsTrusted()

	return v.storeTrustReport(hostID, &hvsReportCollection[0].TrustReport, &samlReport), nil
}

func (v *Verifier) storeTrustReport(hostID uuid.UUID, trustReport *hvs.TrustReport, samlReport *saml.SamlAssertion) *models.HVSReport {
	defaultLog.Trace("hosttrust/verifier:storeTrustReport() Entering")
	defer defaultLog.Trace("hosttrust/verifier:storeTrustReport() Leaving")

	log.Debugf("hosttrust/verifier:storeTrustReport() flavorverify host: %s SAML Report: %s", hostID, samlReport.Assertion)
	hvsReport := models.HVSReport{
		HostID:      hostID,
		TrustReport: *trustReport,
		CreatedAt:   samlReport.CreatedTime,
		Expiration:  samlReport.ExpiryTime,
		Saml:        samlReport.Assertion,
	}
	report, err := v.ReportStore.Update(&hvsReport)
	if err != nil {
		log.WithError(err).Errorf("hosttrust/verifier:storeTrustReport() Failed to store Report")
	}
	return report
}
