/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"encoding/xml"

	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"strings"
)

/**
 *
 * @author mullas
 */

// LinuxPlatformFlavor is used to generate various Flavors for a Intel-based Linux host
type LinuxPlatformFlavor struct {
	HostManifest    *hcTypes.HostManifest        `json:"host_manifest"`
	HostInfo        *taModel.HostInfo            `json:"host_info"`
	TagCertificate  *cm.X509AttributeCertificate `json:"tag_certificate"`
	FlavorTemplates []hvs.FlavorTemplate
}

var pfutil util.PlatformFlavorUtil
var sfutil util.SoftwareFlavorUtil

// NewLinuxPlatformFlavor returns an instance of LinuxPlatformFlavor
func NewLinuxPlatformFlavor(hostReport *hcTypes.HostManifest, tagCertificate *cm.X509AttributeCertificate, flavorTemplates []hvs.FlavorTemplate) PlatformFlavor {
	log.Trace("flavor/types/linux_platform_flavor:NewLinuxPlatformFlavor() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:NewLinuxPlatformFlavor() Leaving")

	return LinuxPlatformFlavor{
		HostManifest:    hostReport,
		HostInfo:        &hostReport.HostInfo,
		TagCertificate:  tagCertificate,
		FlavorTemplates: flavorTemplates,
	}
}

// GetFlavorPartRaw extracts the details of the flavor part requested by the
// caller from the host report used during the creation of the PlatformFlavor instance
func (rhelpf LinuxPlatformFlavor) GetFlavorPartRaw(name cf.FlavorPart) ([]cm.Flavor, error) {
	log.Trace("flavor/types/linux_platform_flavor:GetFlavorPartRaw() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:GetFlavorPartRaw() Leaving")

	switch name {
	case cf.FlavorPartPlatform:
		return rhelpf.getPlatformFlavor()
	case cf.FlavorPartOs:
		return rhelpf.getOsFlavor()
	case cf.FlavorPartAssetTag:
		return rhelpf.getAssetTagFlavor()
	case cf.FlavorPartHostUnique:
		return rhelpf.getHostUniqueFlavor()
	case cf.FlavorPartSoftware:
		return rhelpf.getDefaultSoftwareFlavor()
	}
	return nil, cf.UNKNOWN_FLAVOR_PART()
}

// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
func (rhelpf LinuxPlatformFlavor) GetFlavorPartNames() ([]cf.FlavorPart, error) {
	log.Trace("flavor/types/linux_platform_flavor:GetFlavorPartNames() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:GetFlavorPartNames() Leaving")

	flavorPartList := []cf.FlavorPart{cf.FlavorPartPlatform, cf.FlavorPartOs, cf.FlavorPartHostUnique, cf.FlavorPartSoftware, cf.FlavorPartAssetTag}

	return flavorPartList, nil
}

// GetPcrList Helper function to calculate the list of PCRs for the flavor part specified based
// on the version of the TPM hardware.
func (rhelpf LinuxPlatformFlavor) getPcrList(flavorPart cf.FlavorPart, flavorTemplates []hvs.FlavorTemplate) map[hvs.PCR]hvs.PcrListRules {
	log.Trace("flavor/types/linux_platform_flavor:getPcrList() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getPcrList() Leaving")

	pcrlistAndRules := make(map[hvs.PCR]hvs.PcrListRules)
	for _, flavorTemplate := range flavorTemplates {
		switch flavorPart {
		case cf.FlavorPartPlatform:
			pcrlistAndRules = getPCRListAndRules(flavorTemplate.FlavorParts.Platform, pcrlistAndRules)
			break
		case cf.FlavorPartOs:
			pcrlistAndRules = getPCRListAndRules(flavorTemplate.FlavorParts.OS, pcrlistAndRules)
			break
		case cf.FlavorPartHostUnique:
			pcrlistAndRules = getPCRListAndRules(flavorTemplate.FlavorParts.HostUnique, pcrlistAndRules)
			break
		}
	}

	return pcrlistAndRules
}

func getPCRListAndRules(flavorPart *hvs.FlavorPart, pcrList map[hvs.PCR]hvs.PcrListRules) map[hvs.PCR]hvs.PcrListRules {
	log.Trace("flavor/types/linux_platform_flavor:getPCRListAndRules() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getPCRListAndRules() Leaving")

	if flavorPart == nil {
		return pcrList
	}

	if pcrList == nil {
		pcrList = make(map[hvs.PCR]hvs.PcrListRules)
	}

	for _, pcrRule := range flavorPart.PcrRules {
		var rulesList hvs.PcrListRules

		if rules, ok := pcrList[pcrRule.Pcr]; ok {
			rulesList = rules
		}
		if pcrRule.PcrMatches != nil && *pcrRule.PcrMatches {
			rulesList.PcrMatches = true
		}

		if pcrRule.EventlogEquals != nil {
			rulesList.PcrEquals.IsPcrEquals = true
			if pcrRule.EventlogEquals.ExculdingTags != nil {
				rulesList.PcrEquals.ExcludingTags = make(map[string]bool)
				for _, tags := range pcrRule.EventlogEquals.ExculdingTags {
					if _, ok := rulesList.PcrEquals.ExcludingTags[tags]; !ok {
						rulesList.PcrEquals.ExcludingTags[tags] = false
					}
				}
			}
		}

		if pcrRule.EventlogIncludes != nil {
			rulesList.PcrIncludes = make(map[string]bool)
			for _, tags := range pcrRule.EventlogIncludes {
				if _, ok := rulesList.PcrIncludes[tags]; !ok {
					rulesList.PcrIncludes[tags] = true
				}
			}
		}
		pcrList[pcrRule.Pcr] = rulesList
	}
	log.Debug("flavor/types/linux_platform_flavor:getPCRListAndRules() pcrList ended ", pcrList)
	return pcrList
}

func isCbntMeasureProfile(cbnt *taModel.CBNT) bool {
	log.Trace("flavor/types/linux_platform_flavor:isCbntMeasureProfile() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:isCbntMeasureProfile() Leaving")

	if cbnt != nil {
		return cbnt.Enabled && cbnt.Meta.Profile == cf.BootGuardProfile5().Name
	}
	return false
}

// eventLogRequired Helper function to determine if the event log associated with the PCR
// should be included in the flavor for the specified flavor part
func (rhelpf LinuxPlatformFlavor) eventLogRequired(flavorPartName cf.FlavorPart) bool {
	log.Trace("flavor/types/linux_platform_flavor:eventLogRequired() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:eventLogRequired() Leaving")

	// defaults to false
	var eventLogRequired bool

	switch flavorPartName {
	case cf.FlavorPartPlatform:
		eventLogRequired = true
	case cf.FlavorPartOs:
		eventLogRequired = true
	case cf.FlavorPartHostUnique:
		eventLogRequired = true
	case cf.FlavorPartSoftware:
		eventLogRequired = true
	}
	return eventLogRequired
}

// getPlatformFlavor returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the PLATFORM trust of a host
func (rhelpf LinuxPlatformFlavor) getPlatformFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/linux_platform_flavor:getPlatformFlavor() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getPlatformFlavor() Leaving")

	var errorMessage = "Error during creation of PLATFORM flavor"
	platformPcrs := rhelpf.getPcrList(cf.FlavorPartPlatform, rhelpf.FlavorTemplates)
	var includeEventLog = rhelpf.eventLogRequired(cf.FlavorPartPlatform)
	var allPcrDetails = rhelpf.GetPcrDetails(rhelpf.HostManifest.PcrManifest, platformPcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(rhelpf.HostInfo, rhelpf.TagCertificate, "", cf.FlavorPartPlatform,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failure in Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(cf.FlavorPartPlatform, newMeta, rhelpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failure in Updating Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(rhelpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf(errorMessage + " - failure in Bios section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor() New Bios Section: %v", *newBios)

	newHW := pfutil.GetHardwareSectionDetails(rhelpf.HostInfo)
	if newHW == nil {
		return nil, errors.Errorf(errorMessage + " - failure in Hardware section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor() New Hardware Section: %v", *newHW)

	// Assemble the Platform Flavor
	platformFlavor := cm.NewFlavor(newMeta, newBios, newHW, nil, allPcrDetails, nil, nil)

	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor()  New PlatformFlavor: %v", platformFlavor)

	return []cm.Flavor{*platformFlavor}, nil
}

// getOsFlavor Returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the OS Trust of a host
func (rhelpf LinuxPlatformFlavor) getOsFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/linux_platform_flavor:getOsFlavor() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getOsFlavor() Leaving")

	var errorMessage = "Error during creation of OS flavor"
	var err error
	osPcrs := rhelpf.getPcrList(cf.FlavorPartOs, rhelpf.FlavorTemplates)
	var includeEventLog = rhelpf.eventLogRequired(cf.FlavorPartOs)
	var allPcrDetails = rhelpf.GetPcrDetails(
		rhelpf.HostManifest.PcrManifest, osPcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(rhelpf.HostInfo, rhelpf.TagCertificate, "", cf.FlavorPartOs,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getOsFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(cf.FlavorPartOs, newMeta, rhelpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failure in Updating Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)
	newBios := pfutil.GetBiosSectionDetails(rhelpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf("%s Failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/linux_platform_flavor:getOsFlavor() New Bios Section: %v", *newBios)

	// Assemble the OS Flavor
	osFlavor := cm.NewFlavor(newMeta, newBios, nil, nil, allPcrDetails, nil, nil)

	log.Debugf("flavor/types/linux_platform_flavor:getOSFlavor()  New OS Flavor: %v", osFlavor)

	return []cm.Flavor{*osFlavor}, nil
}

// getHostUniqueFlavor Returns a json document having all the good known PCR values and corresponding event logs that
// can be used for evaluating the unique part of the PCR configurations of a host. These include PCRs/modules getting
// extended to PCRs that would vary from host to host.
func (rhelpf LinuxPlatformFlavor) getHostUniqueFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/linux_platform_flavor:getHostUniqueFlavor() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getHostUniqueFlavor() Leaving")

	var errorMessage = "Error during creation of HOST_UNIQUE flavor"
	var err error
	hostUniquePcrs := rhelpf.getPcrList(cf.FlavorPartHostUnique, rhelpf.FlavorTemplates)
	var includeEventLog = rhelpf.eventLogRequired(cf.FlavorPartHostUnique)
	var allPcrDetails = rhelpf.GetPcrDetails(
		rhelpf.HostManifest.PcrManifest, hostUniquePcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(rhelpf.HostInfo, rhelpf.TagCertificate, "", cf.FlavorPartHostUnique,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getHostUniqueFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(cf.FlavorPartHostUnique, newMeta, rhelpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failure in Updating Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(rhelpf.HostInfo)
	if newBios == nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Bios section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getHostUniqueFlavor() New Bios Section: %v", *newBios)

	// Assemble the Host Unique Flavor
	hostUniqueFlavor := cm.NewFlavor(newMeta, newBios, nil, nil, allPcrDetails, nil, nil)

	log.Debugf("flavor/types/esx_platform_flavor:getHostUniqueFlavor() New PlatformFlavor: %v", hostUniqueFlavor)

	return []cm.Flavor{*hostUniqueFlavor}, nil
}

// getAssetTagFlavor Retrieves the asset tag part of the flavor including the certificate and all the key-value pairs
// that are part of the certificate.
func (rhelpf LinuxPlatformFlavor) getAssetTagFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/linux_platform_flavor:getAssetTagFlavor() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getAssetTagFlavor() Leaving")

	var errorMessage = "Error during creation of ASSET_TAG flavor"
	var err error
	if rhelpf.TagCertificate == nil {
		return nil, errors.Errorf("%s - %s", errorMessage, cf.FLAVOR_PART_CANNOT_BE_SUPPORTED().Message)
	}

	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(rhelpf.HostInfo, rhelpf.TagCertificate, "", cf.FlavorPartAssetTag,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getAssetTagFlavor() New Meta Section: %v", *newMeta)

	// create bios section details
	newBios := pfutil.GetBiosSectionDetails(rhelpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf("%s - Failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/linux_platform_flavor:getAssetTagFlavor() New Bios Section: %v", *newBios)

	// create external section details
	newExt, err := pfutil.GetExternalConfigurationDetails(rhelpf.TagCertificate)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in External configuration section details")
	}
	log.Debugf("flavor/types/linux_platform_flavor:getAssetTagFlavor() New External Section: %v", *newExt)

	// Assemble the Asset Tag Flavor
	assetTagFlavor := cm.NewFlavor(newMeta, newBios, nil, nil, nil, newExt, nil)

	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New Asset Tag Flavor: %v", assetTagFlavor)

	return []cm.Flavor{*assetTagFlavor}, nil
}

// getDefaultSoftwareFlavor Method to create a software flavor. This method would create a software flavor that would
// include all the measurements provided from host.
func (rhelpf LinuxPlatformFlavor) getDefaultSoftwareFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/linux_platform_flavor:getDefaultSoftwareFlavor() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getDefaultSoftwareFlavor() Leaving")

	var softwareFlavors []cm.Flavor
	var errorMessage = cf.SOFTWARE_FLAVOR_CANNOT_BE_CREATED().Message

	if rhelpf.HostManifest != nil && rhelpf.HostManifest.MeasurementXmls != nil {
		measurementXmls, err := rhelpf.getDefaultMeasurement()
		if err != nil {
			return nil, errors.Wrapf(err, errorMessage)
		}

		for _, measurementXml := range measurementXmls {
			var softwareFlavor = NewSoftwareFlavor(measurementXml)
			swFlavor, err := softwareFlavor.GetSoftwareFlavor()
			if err != nil {
				return nil, err
			}
			softwareFlavors = append(softwareFlavors, *swFlavor)
		}
	}
	log.Debugf("flavor/types/linux_platform_flavor:getDefaultSoftwareFlavor() New Software Flavor: %v", softwareFlavors)
	return softwareFlavors, nil
}

// getDefaultMeasurement returns a default set of measurements for the Platform Flavor
func (rhelpf LinuxPlatformFlavor) getDefaultMeasurement() ([]string, error) {
	log.Trace("flavor/types/linux_platform_flavor:getDefaultMeasurement() Entering")
	defer log.Trace("flavor/types/linux_platform_flavor:getDefaultMeasurement() Leaving")

	var measurementXmlCollection []string
	var err error

	for _, measurementXML := range rhelpf.HostManifest.MeasurementXmls {
		var measurement taModel.Measurement
		err = xml.Unmarshal([]byte(measurementXML), &measurement)
		if err != nil {
			return nil, errors.Wrapf(err, "Error unmarshalling measurement XML: %s", err.Error())
		}
		if strings.Contains(measurement.Label, constants.DefaultSoftwareFlavorPrefix) ||
			strings.Contains(measurement.Label, constants.DefaultWorkloadFlavorPrefix) {
			measurementXmlCollection = append(measurementXmlCollection, measurementXML)
			log.Debugf("flavor/types/esx_platform_flavor:getDefaultMeasurement() Measurement XML: %s", measurementXML)
		}
	}
	return measurementXmlCollection, nil
}

// GetPcrDetails extracts Pcr values and Event Logs from the HostManifest/PcrManifest and  returns
// in a format suitable for inserting into the flavor
func (rhelpf LinuxPlatformFlavor) GetPcrDetails(pcrManifest hcTypes.PcrManifest, pcrList map[hvs.PCR]hvs.PcrListRules, includeEventLog bool) []hcTypes.PCRS {
	log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Leaving")

	var pcrCollection []hcTypes.PCRS

	// pull out the logs for the required PCRs from both banks
	for pcr, rules := range pcrList {

		pI := hcTypes.PcrIndex(pcr.Index)
		var pcrInfo *hcTypes.Pcr
		pcrInfo, _ = pcrManifest.GetPcrValue(hcTypes.SHAAlgorithm(pcr.Bank), pI)

		if pcrInfo != nil {

			var currPcrEx hcTypes.PCRS

			currPcrEx.PCR.Index = pcr.Index
			currPcrEx.PCR.Bank = pcr.Bank
			currPcrEx.Measurement = pcrInfo.Value
			currPcrEx.PCRMatches = true

			// Populate Value
			// Event logs if allowed
			if includeEventLog {
				var eventLogEqualEvents []hcTypes.EventLogCriteria
				manifestPcrEventLogs, err := pcrManifest.GetPcrEventLogNew(hcTypes.SHAAlgorithm(pcr.Bank), pI)

				// check if returned logset from PCR is nil
				if manifestPcrEventLogs != nil && err == nil {

					// Convert EventLog to flavor format
					for _, manifestEventLog := range manifestPcrEventLogs {
						if len(manifestEventLog.Tags) == 0 {
							if rules.PcrEquals.IsPcrEquals {
								eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
							}
						}
						for _, tag := range manifestEventLog.Tags {
							if _, ok := rules.PcrIncludes[tag]; ok {
								currPcrEx.EventlogIncludes = append(currPcrEx.EventlogIncludes, manifestEventLog)
							} else if rules.PcrEquals.IsPcrEquals {
								if _, ok := rules.PcrEquals.ExcludingTags[tag]; !ok {
									eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
								}
							}
						}
					}
					if rules.PcrEquals.IsPcrEquals {
						var EventLogExcludes []string
						for excludeTag, _ := range rules.PcrEquals.ExcludingTags {
							EventLogExcludes = append(EventLogExcludes, excludeTag)
						}
						currPcrEx.EventlogEqual = &hcTypes.EventLogEqual{
							Events:      eventLogEqualEvents,
							ExcludeTags: EventLogExcludes,
						}
					}
				}
			}

			pcrCollection = append(pcrCollection, currPcrEx)
		}
	}
	// return map for flavor to use
	return pcrCollection
}

func UpdateMetaSectionDetails(flavorPart cf.FlavorPart, newMeta *cm.Meta, flavorTemplates []hvs.FlavorTemplate) *cm.Meta {
	log.Trace("flavor/util/platform_flavor_util:UpdateMetaSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:UpdateMetaSectionDetails() Leaving")

	var flavorTemplateID []uuid.UUID
	for _, flavorTemplate := range flavorTemplates {
		flavorTemplateID = append(flavorTemplateID, flavorTemplate.ID)
		var flavor *hvs.FlavorPart
		switch flavorPart {
		case cf.FlavorPartPlatform:
			flavor = flavorTemplate.FlavorParts.Platform
		case cf.FlavorPartOs:
			flavor = flavorTemplate.FlavorParts.OS
		case cf.FlavorPartHostUnique:
			flavor = flavorTemplate.FlavorParts.HostUnique
		}

		if flavor != nil {
			log.Info(flavor.Meta)
			newMeta.Description["flavor_template_ids"] = flavorTemplateID
			for key, value := range flavor.Meta {
				log.Info(key)
				newMeta.Description[key] = value
			}
		}
	}
	return newMeta
}
