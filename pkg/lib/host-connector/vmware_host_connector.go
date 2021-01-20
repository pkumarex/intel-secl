/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/vmware"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vim25/mo"
	vim25Types "github.com/vmware/govmomi/vim25/types"
)

type VmwareConnector struct {
	client vmware.VMWareClient
}

const (
	TPM_SOFTWARE_COMPONENT_EVENT_TYPE   = "HostTpmSoftwareComponentEvent"
	TPM_COMMAND_EVENT_TYPE              = "HostTpmCommandEvent"
	TPM_OPTION_EVENT_TYPE               = "HostTpmOptionEvent"
	TPM_BOOT_SECURITY_OPTION_EVENT_TYPE = "HostTpmBootSecurityOptionEvent"
	COMPONENT_PREFIX                    = "componentName."
	COMMANDLINE_PREFIX                  = "commandLine."
	VIM_API_PREFIX                      = "Vim25Api."
	DETAILS_SUFFIX                      = "Details"
	BOOT_OPTIONS_PREFIX                 = "bootOptions."
	BOOT_SECURITY_OPTIONS_PREFIX        = "bootSecurityOption."
)

func (vc *VmwareConnector) GetHostDetails() (taModel.HostInfo, error) {

	log.Trace("vmware_host_connector :GetHostDetails() Entering")
	defer log.Trace("vmware_host_connector :GetHostDetails() Leaving")
	hostInfo, err := vc.client.GetHostInfo()
	if err != nil {
		return taModel.HostInfo{}, errors.Wrap(err, "vmware_host_connector: GetHostDetails() Error getting host"+
			"info from vmware")
	}
	return hostInfo, nil
}

func (vc *VmwareConnector) GetHostManifest() (types.HostManifest, error) {

	log.Trace("vmware_host_connector :GetHostManifest() Entering")
	defer log.Trace("vmware_host_connector :GetHostManifest() Leaving")
	var err error
	var hostManifest types.HostManifest
	var pcrManifest types.PcrManifest
	tpmAttestationReport, err := vc.client.GetTPMAttestationReport()
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "vmware_host_connector: GetHostManifest() Error getting TPM "+
			"attestation report from vcenter API")
	}

	//Check if TPM log is reliable
	if !tpmAttestationReport.Returnval.TpmLogReliable {
		return types.HostManifest{}, errors.New("vmware_host_connector: GetHostManifest() TPM log received from" +
			"VMware host is not reliable")
	}
	pcrManifest, err = createPCRManifest(tpmAttestationReport.Returnval)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "vmware_host_connector: GetHostManifest() Error parsing "+
			"PCR manifest from Host Attestation Report")
	}

	hostManifest.HostInfo, err = vc.client.GetHostInfo()
	log.Debugf("Host info received : %v", hostManifest.HostInfo)
	if err != nil {
		return types.HostManifest{}, errors.Wrap(err, "vmware_host_connector: GetHostManifest() Error getting host "+
			"info from vcenter API")
	}
	hostManifest.PcrManifest = pcrManifest
	return hostManifest, nil
}

func (vc *VmwareConnector) DeployAssetTag(hardwareUUID, tag string) error {
	return errors.New("vmware_host_connector:DeployAssetTag() Operation not supported")
}

func (vc *VmwareConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {
	return errors.New("vmware_host_connector :DeploySoftwareManifest() Operation not supported")
}

func (vc *VmwareConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	return taModel.Measurement{}, errors.New("vmware_host_connector :GetMeasurementFromManifest() Operation not supported")
}

func (vc *VmwareConnector) GetClusterReference(clusterName string) ([]mo.HostSystem, error) {
	log.Trace("vmware_host_connector :GetClusterReference() Entering")
	defer log.Trace("vmware_host_connector :GetClusterReference() Leaving")
	hostInfoList, err := vc.client.GetVmwareClusterReference(clusterName)
	if err != nil {
		return nil, errors.Wrap(err, "vmware_host_connector: GetClusterReference() Error getting host"+
			"info from vmware")
	}
	return hostInfoList, nil
}

func createPCRManifest(hostTpmAttestationReport *vim25Types.HostTpmAttestationReport) (types.PcrManifest, error) {

	log.Trace("vmware_host_connector :createPCRManifest() Entering")
	defer log.Trace("vmware_host_connector :createPCRManifest() Leaving")

	var pcrManifest types.PcrManifest
	pcrManifest.Sha256Pcrs = []types.Pcr{}
	pcrManifest.Sha1Pcrs = []types.Pcr{}
	var pcrEventLogMap types.PcrEventLogMap

	for _, pcrDetails := range hostTpmAttestationReport.TpmPcrValues {
		pcrIndex, err := types.GetPcrIndexFromString(strconv.Itoa(int(pcrDetails.PcrNumber)))
		if err != nil {
			return pcrManifest, err
		}
		shaAlgorithm, err := types.GetSHAAlgorithm(pcrDetails.DigestMethod)
		if err != nil {
			return pcrManifest, err
		}
		if strings.EqualFold(pcrDetails.DigestMethod, "SHA256") {
			pcrManifest.Sha256Pcrs = append(pcrManifest.Sha256Pcrs, types.Pcr{
				Index:   pcrIndex,
				Value:   intArrayToHexString(pcrDetails.DigestValue),
				PcrBank: shaAlgorithm,
			})
		} else if strings.EqualFold(pcrDetails.DigestMethod, "SHA1") {
			pcrManifest.Sha1Pcrs = append(pcrManifest.Sha1Pcrs, types.Pcr{
				Index:   pcrIndex,
				Value:   intArrayToHexString(pcrDetails.DigestValue),
				PcrBank: shaAlgorithm,
			})
		} else {
			log.Warn("vmware_host_connector:createPCRManifest() Result PCR invalid")
		}
	}
	pcrEventLogMap, err := getPcrEventLog(hostTpmAttestationReport.TpmEvents, pcrEventLogMap)
	if err != nil {
		log.Errorf("vmware_host_connector:createPCRManifest() Error getting PCR event log : %s", err.Error())
		return pcrManifest, errors.Wrap(err, "vmware_host_connector:createPCRManifest() Error getting PCR "+
			"event log")
	}

	pcrManifest.PcrEventLogMap = pcrEventLogMap
	return pcrManifest, nil
}

func getPcrEventLog(hostTpmEventLogEntry []vim25Types.HostTpmEventLogEntry, eventLogMap types.PcrEventLogMap) (types.PcrEventLogMap, error) {

	log.Trace("vmware_host_connector:getPcrEventLog() Entering")
	defer log.Trace("vmware_host_connector:getPcrEventLog() Leaving")

	var pcrIndex types.PcrIndex
	eventLogMap.Sha1EventLogs = []types.EventLogEntry{}
	eventLogMap.Sha256EventLogs = []types.EventLogEntry{}

	for _, eventLogEntry := range hostTpmEventLogEntry {
		pcrFound := false
		index := 0
		parsedEventLogEntry := types.TpmEvent{}
		//This is done to preserve the dynamic data i.e the info of the event details
		marshalledEntry, err := json.Marshal(eventLogEntry)
		log.Debugf("Marshalled event log : %s", string(marshalledEntry))
		if err != nil {
			return types.PcrEventLogMap{}, errors.Wrap(err, "vmware_host_connector:getPcrEventLog() Error "+
				"unmarshalling TPM event")
		}
		//Unmarshal to structure to get the inaccessible fields from event details JSON
		err = json.Unmarshal(marshalledEntry, &parsedEventLogEntry)
		if err != nil {
			return types.PcrEventLogMap{}, err
		}
		pcrIndex, err = types.GetPcrIndexFromString(strconv.Itoa(parsedEventLogEntry.PcrIndex))
		if err != nil {
			return types.PcrEventLogMap{}, err
		}
		//vCenter 6.5 only supports SHA1 digest and hence do not have digest method field. Also if the hash is 0 they
		//send out 40 0s instead of 20
		if len(parsedEventLogEntry.EventDetails.DataHash) == 20 || len(parsedEventLogEntry.EventDetails.DataHash) == 40 {
			parsedEventLogEntry.EventDetails.DataHashMethod = "SHA1"
			for _, entry := range eventLogMap.Sha1EventLogs {
				if entry.PcrIndex == pcrIndex {
					pcrFound = true
					break
				}
				index++
			}
			eventLog := getEventLogInfo(parsedEventLogEntry)

			if !pcrFound {
				eventLogMap.Sha1EventLogs = append(eventLogMap.Sha1EventLogs, types.EventLogEntry{PcrIndex: pcrIndex, PcrBank: parsedEventLogEntry.EventDetails.DataHashMethod, EventLogs: []types.EventLog{eventLog}})
			} else {
				eventLogMap.Sha1EventLogs[index].EventLogs = append(eventLogMap.Sha1EventLogs[index].EventLogs, eventLog)
			}
		} else if len(parsedEventLogEntry.EventDetails.DataHash) == 32 {
			parsedEventLogEntry.EventDetails.DataHashMethod = "SHA256"
			for _, entry := range eventLogMap.Sha256EventLogs {
				if entry.PcrIndex == pcrIndex {
					pcrFound = true
					break
				}
				index++
			}

			eventLog := getEventLogInfo(parsedEventLogEntry)

			if !pcrFound {
				eventLogMap.Sha256EventLogs = append(eventLogMap.Sha256EventLogs, types.EventLogEntry{PcrIndex: pcrIndex, PcrBank: parsedEventLogEntry.EventDetails.DataHashMethod, EventLogs: []types.EventLog{eventLog}})
			} else {
				eventLogMap.Sha256EventLogs[index].EventLogs = append(eventLogMap.Sha256EventLogs[index].EventLogs, eventLog)
			}
		}

	}

	//Sort the event log map so that the PCR indices are in order
	sort.SliceStable(eventLogMap.Sha1EventLogs[:], func(i, j int) bool {
		return string(eventLogMap.Sha1EventLogs[i].PcrIndex) < string(eventLogMap.Sha1EventLogs[j].PcrIndex)
	})

	sort.SliceStable(eventLogMap.Sha256EventLogs[:], func(i, j int) bool {
		return string(eventLogMap.Sha256EventLogs[i].PcrIndex) < string(eventLogMap.Sha256EventLogs[j].PcrIndex)
	})

	log.Debug("vmware_host_connector:getPcrEventLog() PCR event log created")
	return eventLogMap, nil
}

func intArrayToHexString(pcrDigestArray []int) string {
	log.Trace("vmware_host_connector:intArrayToHexString() Entering")
	defer log.Trace("vmware_host_connector:intArrayToHexString() Leaving")
	var pcrDigestString string

	//if the hash is 0 then vcenter 6.5 API sends out 40 0s instead of 20 for SHA1
	if len(pcrDigestArray) == 40 {
		pcrDigestArray = pcrDigestArray[0:20]
	}

	for _, element := range pcrDigestArray {
		if element < 0 {
			element = 256 + element
		}
		pcrDigestString += fmt.Sprintf("%02x", element)
	}
	return pcrDigestString
}

//It checks the type of TPM event and accordingly updates the event log entry values
func getEventLogInfo(parsedEventLogEntry types.TpmEvent) types.EventLog {

	log.Trace("vmware_host_connector:getEventLogInfo() Entering")
	defer log.Trace("vmware_host_connector:getEventLogInfo() Leaving")
	eventLog := types.EventLog{Value: intArrayToHexString(parsedEventLogEntry.EventDetails.DataHash)}
	eventLog.Info = make(map[string]string)

	if parsedEventLogEntry.EventDetails.VibName != nil {
		eventLog.Label = *parsedEventLogEntry.EventDetails.ComponentName
		eventLog.Info["EventType"] = TPM_SOFTWARE_COMPONENT_EVENT_TYPE
		eventLog.Info["ComponentName"] = COMPONENT_PREFIX + *parsedEventLogEntry.EventDetails.ComponentName
		eventLog.Info["EventName"] = VIM_API_PREFIX + TPM_SOFTWARE_COMPONENT_EVENT_TYPE + DETAILS_SUFFIX
		if parsedEventLogEntry.EventDetails.VibName != nil {
			eventLog.Info["PackageName"] = *parsedEventLogEntry.EventDetails.VibName
		}
		if parsedEventLogEntry.EventDetails.VibVendor != nil {
			eventLog.Info["PackageVendor"] = *parsedEventLogEntry.EventDetails.VibVendor
		}
		if parsedEventLogEntry.EventDetails.VibVersion != nil {
			eventLog.Info["PackageVersion"] = *parsedEventLogEntry.EventDetails.VibVersion
		}

		if parsedEventLogEntry.PcrIndex == 19 {
			eventLog.Info["FullComponentName"] = "componentName." + (*parsedEventLogEntry.EventDetails.ComponentName)[0:strings.Index(*parsedEventLogEntry.EventDetails.ComponentName, ".")] + "-" +
				*parsedEventLogEntry.EventDetails.VibName + "-" + *parsedEventLogEntry.EventDetails.VibVersion
		}
	} else if parsedEventLogEntry.EventDetails.CommandLine != nil {
		uuid := getBootUUIDFromCL(*parsedEventLogEntry.EventDetails.CommandLine)
		if uuid != "" {
			eventLog.Info["UUID"] = uuid
			eventLog.Info["ComponentName"] = COMMANDLINE_PREFIX
		} else {
			eventLog.Info["ComponentName"] = COMMANDLINE_PREFIX + *parsedEventLogEntry.EventDetails.CommandLine
		}
		eventLog.Label = *parsedEventLogEntry.EventDetails.CommandLine
		eventLog.Info["EventType"] = TPM_COMMAND_EVENT_TYPE
		eventLog.Info["EventName"] = VIM_API_PREFIX + TPM_COMMAND_EVENT_TYPE + DETAILS_SUFFIX

	} else if parsedEventLogEntry.EventDetails.OptionsFileName != nil {
		eventLog.Label = *parsedEventLogEntry.EventDetails.OptionsFileName
		eventLog.Info["EventType"] = TPM_OPTION_EVENT_TYPE
		eventLog.Info["ComponentName"] = BOOT_OPTIONS_PREFIX + *parsedEventLogEntry.EventDetails.OptionsFileName
		eventLog.Info["EventName"] = VIM_API_PREFIX + TPM_OPTION_EVENT_TYPE + DETAILS_SUFFIX

	} else if parsedEventLogEntry.EventDetails.BootSecurityOption != nil {
		eventLog.Label = *parsedEventLogEntry.EventDetails.BootSecurityOption
		eventLog.Info["EventType"] = TPM_BOOT_SECURITY_OPTION_EVENT_TYPE
		eventLog.Info["ComponentName"] = BOOT_SECURITY_OPTIONS_PREFIX + *parsedEventLogEntry.EventDetails.BootSecurityOption
		eventLog.Info["EventName"] = VIM_API_PREFIX + TPM_BOOT_SECURITY_OPTION_EVENT_TYPE + DETAILS_SUFFIX
	} else {
		log.Warn("Unrecognized event in module event log")
	}

	return eventLog
}

func getBootUUIDFromCL(commandLine string) string {
	log.Trace("vmware_host_connector:getBootUUIDFromCL() Entering")
	defer log.Trace("vmware_host_connector:getBootUUIDFromCL() Leaving")
	for _, word := range strings.Split(commandLine, " ") {
		if strings.Contains(word, "bootUUID") {
			return strings.Split(word, "=")[1]
		}
	}
	return ""
}
