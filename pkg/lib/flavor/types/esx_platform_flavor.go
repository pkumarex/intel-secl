/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

/**
 *
 * @author mullas
 */

import (
	"crypto"
	"encoding/hex"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

var (
	// This is a map of host specific modules.
	// The map value (int) is not relevant, just use the map key for efficient lookups.
	hostSpecificModules = map[string]int{
		"commandLine.":              0,
		"componentName.imgdb.tgz":   0,
		"componentName.onetime.tgz": 0,
	}
)

// ESXPlatformFlavor is used to generate various Flavors for a VMWare ESX-based host
type ESXPlatformFlavor struct {
	HostManifest    *hcTypes.HostManifest        `json:"host_manifest"`
	HostInfo        *taModel.HostInfo            `json:"host_info"`
	TagCertificate  *cm.X509AttributeCertificate `json:"tag_certificate"`
	FlavorTemplates []hvs.FlavorTemplate
}

// NewESXPlatformFlavor returns an instance of ESXPlaformFlavor
func NewESXPlatformFlavor(manifest *hcTypes.HostManifest, tagCertificate *cm.X509AttributeCertificate, flavorTemplates []hvs.FlavorTemplate) PlatformFlavor {
	log.Trace("flavor/types/esx_platform_flavor:NewESXPlatformFlavor() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:NewESXPlatformFlavor() Leaving")

	return ESXPlatformFlavor{
		HostManifest:    manifest,
		HostInfo:        &manifest.HostInfo,
		TagCertificate:  tagCertificate,
		FlavorTemplates: flavorTemplates,
	}
}

// GetFlavorPartRaw extracts the details of the flavor part requested by the
// caller from the host report used during the creation of the PlatformFlavor instance
func (esxpf ESXPlatformFlavor) GetFlavorPartRaw(name cf.FlavorPart) ([]cm.Flavor, error) {
	log.Trace("flavor/types/esx_platform_flavor:GetFlavorPartRaw() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:GetFlavorPartRaw() Leaving")

	switch name {
	case cf.FlavorPartPlatform:
		return esxpf.getPlatformFlavor()
	case cf.FlavorPartOs:
		return esxpf.getOsFlavor()
	case cf.FlavorPartAssetTag:
		return esxpf.getAssetTagFlavor()
	case cf.FlavorPartHostUnique:
		return esxpf.getHostUniqueFlavor()
	}
	return nil, cf.UNKNOWN_FLAVOR_PART()
}

func (esxpf ESXPlatformFlavor) GetFlavorPartNames() ([]cf.FlavorPart, error) {
	log.Trace("flavor/types/esx_platform_flavor:GetFlavorPartNames() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:GetFlavorPartNames() Leaving")

	return []cf.FlavorPart{
		cf.FlavorPartPlatform, cf.FlavorPartOs,
		cf.FlavorPartHostUnique, cf.FlavorPartAssetTag}, nil
}

// eventLogRequiredForEsx Helper function to determine if the event log associated with the PCR
// should be included in the flavor for the specified flavor part
func eventLogRequiredForEsx(tpmVersion string, flavorPartName cf.FlavorPart) bool {
	log.Trace("flavor/types/esx_platform_flavor:eventLogRequiredForEsx() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:eventLogRequiredForEsx() Leaving")

	var eventLogRequired bool

	switch flavorPartName {
	case cf.FlavorPartPlatform:
		if tpmVersion == constants.TPMVersion2 {
			eventLogRequired = true
		}
	case cf.FlavorPartOs:
		eventLogRequired = true
	case cf.FlavorPartHostUnique:
		eventLogRequired = true
	case cf.FlavorPartAssetTag:
		eventLogRequired = false
	case cf.FlavorPartSoftware:
		eventLogRequired = false
	}
	return eventLogRequired
}

// GetPlatformFlavor returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the PLATFORM trust of a host
func (esxpf ESXPlatformFlavor) getPlatformFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/esx_platform_flavor:getPlatformFlavor() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:getPlatformFlavor() Leaving")

	var errorMessage = "Error during creation of PLATFORM flavor"
	platformPcrs, err := pfutil.GetPcrRulesMap(cf.FlavorPartPlatform, esxpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, "flavor/types/esx_platform_flavor:getPlatformFlavor() "+errorMessage+" Failure in getting pcrlist")
	}
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartPlatform)
	var flavorPcrs = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, platformPcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartPlatform,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - Failure in Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(cf.FlavorPartPlatform, newMeta, esxpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, "flavor/types/esx_platform_flavor:getPlatformFlavor() "+errorMessage+" failure in Updating Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf(errorMessage + " - Failure in Bios section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New Bios Section: %v", *newBios)

	newHW := pfutil.GetHardwareSectionDetails(esxpf.HostInfo)
	if newHW == nil {
		return nil, errors.Errorf(errorMessage + " - Failure in Hardware section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New Hardware Section: %v", *newHW)

	// Assemble the Platform Flavor
	platformFlavor := cm.NewFlavor(newMeta, newBios, newHW, flavorPcrs, nil, nil)

	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New PlatformFlavor: %v", platformFlavor)

	return []cm.Flavor{*platformFlavor}, nil
}

// getOsFlavor Returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the OS Trust of a host
func (esxpf ESXPlatformFlavor) getOsFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/esx_platform_flavor:getOsFlavor() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:getOsFlavor() Leaving")

	var errorMessage = "Error during creation of OS flavor"
	var err error

	osPcrs, err := pfutil.GetPcrRulesMap(cf.FlavorPartOs, esxpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, "flavor/types/esx_platform_flavor:getOsFlavor() "+errorMessage+" Failure in getting pcrlist")
	}
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartOs)

	filteredPcrDetails := pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, osPcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartOs,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - Failure in Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getOsFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(cf.FlavorPartOs, newMeta, esxpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, "flavor/types/esx_platform_flavor:getOsFlavor() "+errorMessage+" failure in Updating Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getOsFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf(errorMessage + " - Failure in Bios section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getOsFlavor() New Bios Section: %v", *newBios)

	// Assemble the OS Flavor
	osFlavor := cm.NewFlavor(newMeta, newBios, nil, filteredPcrDetails, nil, nil)

	log.Debugf("flavor/types/esx_platform_flavor:getOsFlavor() New OS Flavor: %v", osFlavor)

	return []cm.Flavor{*osFlavor}, nil
}

// getHostUniquesFlavor returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the unique part
// of the PCR configurations of a host. These include PCRs/modules getting
// extended to PCRs that would vary from host to host.
func (esxpf ESXPlatformFlavor) getHostUniqueFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/esx_platform_flavor:getHostUniqueFlavor() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:getHostUniqueFlavor() Leaving")

	var errorMessage = "Error during creation of HOST_UNIQUE flavor"
	var err error

	hostUniquePcrs, err := pfutil.GetPcrRulesMap(cf.FlavorPartHostUnique, esxpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, "flavor/types/esx_platform_flavor:getHostUniqueFlavor() "+errorMessage+" Failure in getting pcrlist")
	}
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartHostUnique)

	var flavorPcrs = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, hostUniquePcrs, includeEventLog)

	// Assemble Meta and Bios information for HOST_UNIQUE flavor
	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartHostUnique,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getHostUniqueFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(cf.FlavorPartHostUnique, newMeta, esxpf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrap(err, "flavor/types/esx_platform_flavor:getHostUniqueFlavor() "+errorMessage+" failure in Updating Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Bios section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getHostUniqueFlavor() New Bios Section: %v", *newBios)

	// Assemble the HOST_UNIQUE Flavor
	hostUniqueFlavors := cm.NewFlavor(newMeta, newBios, nil, flavorPcrs, nil, nil)
	log.Debugf("flavor/types/esx_platform_flavor:getHostUniqueFlavor() New HOST_UNIQUE Flavor: %v", hostUniqueFlavors)

	return []cm.Flavor{*hostUniqueFlavors}, nil
}

// getAssetTagFlavor returns the asset tag part of the flavor including the certificate and
// all the key-value pairs that are part of the certificate.
func (esxpf ESXPlatformFlavor) getAssetTagFlavor() ([]cm.Flavor, error) {
	log.Trace("flavor/types/esx_platform_flavor:getAssetTagFlavor() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:getAssetTagFlavor() Leaving")

	var errorMessage = "Error during creation of ASSET_TAG flavor"
	var err error
	var tagCertificateHash []byte
	var expectedPcrValue string

	if esxpf.TagCertificate == nil {
		return nil, errors.Errorf("Tag certificate not specified")
	}

	// calculate the expected PCR 22 value based on tag certificate hash event
	tagCertificateHash, err = crypt.GetHashData(esxpf.TagCertificate.Encoded, crypto.SHA1)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in evaluating certificate digest")
	}

	expectedEventLogEntry := hcTypes.TpmEventLog{
		Pcr: hcTypes.PCR{
			Index: 22,
			Bank:  "SHA1",
		},
		TpmEvent: []hcTypes.EventLogCriteria{
			{
				Measurement: hex.EncodeToString(tagCertificateHash),
			},
		},
	}

	expectedPcrValue, err = expectedEventLogEntry.Replay()
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in evaluating PCR22 value")
	}

	pcrDetails := []hcTypes.PCRS{
		{
			PCR: hcTypes.PCR{
				Index: 22,
				Bank:  "SHA1",
			},
			Measurement: expectedPcrValue,
			PCRMatches:  true,
		},
	}

	// Assemble meta and bios details
	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartAssetTag,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getAssetTagFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf("%s Failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/esx_platform_flavor:getAssetTagFlavor() New Bios Section: %v", *newBios)

	newExtConfig, err := pfutil.GetExternalConfigurationDetails(esxpf.TagCertificate)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in External Configuration section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getAssetTagFlavor() New External Section: %v", *newExtConfig)

	// Assemble the ASSET_TAG Flavor
	assetTagFlavor := cm.NewFlavor(newMeta, newBios, nil, pcrDetails, newExtConfig, nil)

	log.Debugf("flavor/types/esx_platform_flavor:getAssetTagFlavor() New Asset Tag Flavor: %v", assetTagFlavor)

	return []cm.Flavor{*assetTagFlavor}, nil
}
