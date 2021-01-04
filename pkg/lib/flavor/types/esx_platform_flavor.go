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
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
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
	HostManifest   *hcTypes.HostManifest        `json:"host_manifest"`
	HostInfo       *taModel.HostInfo            `json:"host_info"`
	TagCertificate *cm.X509AttributeCertificate `json:"tag_certificate"`
}

// NewESXPlatformFlavor returns an instance of ESXPlaformFlavor
func NewESXPlatformFlavor(manifest *hcTypes.HostManifest, tagCertificate *cm.X509AttributeCertificate) PlatformFlavor {
	log.Trace("flavor/types/esx_platform_flavor:NewESXPlatformFlavor() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:NewESXPlatformFlavor() Leaving")

	return ESXPlatformFlavor{
		HostManifest:   manifest,
		HostInfo:       &manifest.HostInfo,
		TagCertificate: tagCertificate,
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

// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
func (esxpf ESXPlatformFlavor) GetFlavorPartNames() ([]cf.FlavorPart, error) {
	log.Trace("flavor/types/esx_platform_flavor:GetFlavorPartNames() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:GetFlavorPartNames() Leaving")

	flavorPartList := []cf.FlavorPart{cf.FlavorPartPlatform, cf.FlavorPartOs, cf.FlavorPartHostUnique, cf.FlavorPartSoftware}
	var pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx

	// For each of the flavor parts, check what PCRs are required and if those required PCRs are present in the host report.
	for i := 0; i < len(flavorPartList); i++ {
		flavorPart := flavorPartList[i]
		pcrList := esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, flavorPart)
		pcrExists := pfutil.PcrExists(esxpf.HostManifest.PcrManifest, pcrList)
		if !pcrExists {
			// remove the non-existent FlavorPart from list
			flavorPartList = append(flavorPartList[:i], flavorPartList[i+1:]...)
		}
	}

	// Check if the AssetTag flavor part is available by ascertaining if contents of PCR22 are set
	pcrDetails = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, []int{22}, false)
	if pcrDetails == nil {
		return []cf.FlavorPart{}, errors.Errorf("Error fetching PCR22 Details")
	}

	// loop through till PCR22 is found and then check if it is unset
	for _, digestAlgEntry := range pcrDetails {
		for pcrIndexKey, pcrIndexValue := range digestAlgEntry {
			if pcrIndexKey == hcTypes.PCR22 && strings.ToLower(pcrIndexValue.Value) != strings.ToLower(string(crypt.SHA1().ZeroHash())) {
				flavorPartList = append(flavorPartList, cf.FlavorPartAssetTag)
				break
			}
		}
	}
	return flavorPartList, nil
}

// GetPcrList Helper function to calculate the list of PCRs for the flavor part specified based
// on the version of the TPM hardware. TPM 2.0 support is available since ISecL v1.2
func (esxpf ESXPlatformFlavor) getPcrList(tpmVersion string, flavorPart cf.FlavorPart) []int {
	log.Trace("flavor/types/esx_platform_flavor:getPcrList() Entering")
	defer log.Trace("flavor/types/esx_platform_flavor:getPcrList() Leaving")

	var pcrs []int
	var isTpm20 bool
	isTpm20 = tpmVersion == constants.TPMVersion2
	switch flavorPart {
	case cf.FlavorPartPlatform:
		if isTpm20 {
			pcrs = append(pcrs, []int{0, 17, 18}...)
		} else {
			pcrs = append(pcrs, []int{0, 17}...)
		}
	case cf.FlavorPartOs:
		if isTpm20 {
			pcrs = append(pcrs, []int{19, 20, 21}...)
		} else {
			pcrs = append(pcrs, []int{18, 19, 20}...)
		}
	case cf.FlavorPartHostUnique:
		if isTpm20 {
			pcrs = append(pcrs, []int{20, 21}...)
		} else {
			pcrs = append(pcrs, []int{19}...)
		}

	case cf.FlavorPartAssetTag:
		pcrs = append(pcrs, []int{22}...)
	}
	return pcrs
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
	var platformPcrs = esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartPlatform)
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartPlatform)
	var flavorPcrs = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, platformPcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartPlatform,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - Failure in Meta section details")
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
	platformFlavor := cm.NewFlavor(newMeta, newBios, newHW, flavorPcrs, nil, nil, nil)

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

	var osPcrs = esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartOs)
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartOs)

	pcrAllEventDetails := pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, osPcrs, includeEventLog)
	filteredPcrDetails := pfutil.ExcludeModulesFromEventLog(pcrAllEventDetails, hostSpecificModules)

	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartOs,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - Failure in Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getOsFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf(errorMessage + " - Failure in Bios section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getOsFlavor() New Bios Section: %v", *newBios)

	// Assemble the OS Flavor
	osFlavor := cm.NewFlavor(newMeta, newBios, nil, filteredPcrDetails, nil, nil, nil)

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

	var hostUniquePcrs = esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartHostUnique)
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.FlavorPartHostUnique)

	var pcrDetails = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, hostUniquePcrs, includeEventLog)
	var flavorPcrs = pfutil.IncludeModulesToEventLog(pcrDetails, hostSpecificModules)

	// Assemble Meta and Bios information for HOST_UNIQUE flavor
	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.FlavorPartHostUnique,
		hcConstants.VendorVMware)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getHostUniqueFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Bios section details")
	}
	log.Debugf("flavor/types/esx_platform_flavor:getHostUniqueFlavor() New Bios Section: %v", *newBios)

	// Assemble the HOST_UNIQUE Flavor
	hostUniqueFlavors := cm.NewFlavor(newMeta, newBios, nil, flavorPcrs, nil, nil, nil)
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

	expectedEventLogEntry := hcTypes.EventLogEntry{
		PcrIndex: hcTypes.PCR22,
		PcrBank:  hcTypes.SHA1,
		EventLogs: []hcTypes.EventLog{
			{
				DigestType: util.EVENT_LOG_DIGEST_SHA1,
				Value:      hex.EncodeToString(tagCertificateHash),
			},
		},
	}

	expectedPcrValue, err = expectedEventLogEntry.Replay()
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in evaluating PCR22 value")
	}

	// Add the expected PCR 22 value to respective hash maps
	var pcr22 = make(map[hcTypes.PcrIndex]cm.PcrEx)
	pcr22[hcTypes.PCR22] = *cm.NewPcrEx(expectedPcrValue, nil)
	var pcrDetails = make(map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx)
	pcrDetails[crypt.SHA1()] = pcr22

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
	assetTagFlavor := cm.NewFlavor(newMeta, newBios, nil, pcrDetails, nil, newExtConfig, nil)

	log.Debugf("flavor/types/esx_platform_flavor:getAssetTagFlavor() New Asset Tag Flavor: %v", assetTagFlavor)

	return []cm.Flavor{*assetTagFlavor}, nil
}
