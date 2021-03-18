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
	VIB_NAME_TYPE_ID                    = "0x60000001"
	COMMANDLINE_TYPE_ID                 = "0x60000002"
	OPTIONS_FILE_NAME_TYPE_ID           = "0x60000003"
	BOOT_SECURITY_OPTION_TYPE_ID        = "0x60000004"
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

	eventLogMap.Sha1EventLogs = []types.TpmEventLog{}
	eventLogMap.Sha256EventLogs = []types.TpmEventLog{}

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

		//vCenter 6.5 only supports SHA1 digest and hence do not have digest method field. Also if the hash is 0 they
		//send out 40 0s instead of 20
		if len(parsedEventLogEntry.EventDetails.DataHash) == 20 || len(parsedEventLogEntry.EventDetails.DataHash) == 40 {
			parsedEventLogEntry.EventDetails.DataHashMethod = "SHA1"
			for _, entry := range eventLogMap.Sha1EventLogs {
				if entry.Pcr.Index == parsedEventLogEntry.PcrIndex {
					pcrFound = true
					break
				}
				index++
			}
			eventLog := getEventLogInfo(parsedEventLogEntry)

			if !pcrFound {
				eventLogMap.Sha1EventLogs = append(eventLogMap.Sha1EventLogs, types.TpmEventLog{Pcr: types.PCR{Index: parsedEventLogEntry.PcrIndex, Bank: string(parsedEventLogEntry.EventDetails.DataHashMethod)}, TpmEvent: []types.EventLog{eventLog}})
			} else {
				eventLogMap.Sha1EventLogs[index].TpmEvent = append(eventLogMap.Sha1EventLogs[index].TpmEvent, eventLog)
			}
		} else if len(parsedEventLogEntry.EventDetails.DataHash) == 32 {
			parsedEventLogEntry.EventDetails.DataHashMethod = "SHA256"
			for _, entry := range eventLogMap.Sha256EventLogs {
				if entry.Pcr.Index == parsedEventLogEntry.PcrIndex {
					pcrFound = true
					break
				}
				index++
			}

			eventLog := getEventLogInfo(parsedEventLogEntry)

			if !pcrFound {
				eventLogMap.Sha256EventLogs = append(eventLogMap.Sha256EventLogs,
					types.TpmEventLog{Pcr: types.PCR{Index: parsedEventLogEntry.PcrIndex, Bank: string(parsedEventLogEntry.EventDetails.DataHashMethod)}, TpmEvent: []types.EventLog{eventLog}})
			} else {
				eventLogMap.Sha256EventLogs[index].TpmEvent = append(eventLogMap.Sha256EventLogs[index].TpmEvent, eventLog)
			}
		}

	}

	//Sort the event log map so that the PCR indices are in order
	sort.SliceStable(eventLogMap.Sha1EventLogs[:], func(i, j int) bool {
		return string(eventLogMap.Sha1EventLogs[i].Pcr.Index) < string(eventLogMap.Sha1EventLogs[j].Pcr.Index)
	})

	sort.SliceStable(eventLogMap.Sha256EventLogs[:], func(i, j int) bool {
		return string(eventLogMap.Sha256EventLogs[i].Pcr.Index) < string(eventLogMap.Sha256EventLogs[j].Pcr.Index)
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
	eventLog := types.EventLog{Measurement: intArrayToHexString(parsedEventLogEntry.EventDetails.DataHash)}

	if parsedEventLogEntry.EventDetails.VibName != nil {
		eventLog.TypeID = VIB_NAME_TYPE_ID
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.ComponentName
		eventLog.Tags = append(eventLog.Tags, COMPONENT_PREFIX+*parsedEventLogEntry.EventDetails.ComponentName)
		if *parsedEventLogEntry.EventDetails.VibName != "" {
			eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_SOFTWARE_COMPONENT_EVENT_TYPE+DETAILS_SUFFIX+"_"+*parsedEventLogEntry.EventDetails.VibName+"_"+*parsedEventLogEntry.EventDetails.VibVendor)
		} else {
			eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_SOFTWARE_COMPONENT_EVENT_TYPE+DETAILS_SUFFIX)
		}
	} else if parsedEventLogEntry.EventDetails.CommandLine != nil {
		eventLog.TypeID = COMMANDLINE_TYPE_ID
		uuid := getBootUUIDFromCL(*parsedEventLogEntry.EventDetails.CommandLine)
		if uuid != "" {
			eventLog.Tags = append(eventLog.Tags, COMMANDLINE_PREFIX)
		} else {
			eventLog.Tags = append(eventLog.Tags, COMMANDLINE_PREFIX+*parsedEventLogEntry.EventDetails.CommandLine)
		}
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.CommandLine
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_COMMAND_EVENT_TYPE+DETAILS_SUFFIX)

	} else if parsedEventLogEntry.EventDetails.OptionsFileName != nil {
		eventLog.TypeID = OPTIONS_FILE_NAME_TYPE_ID
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.OptionsFileName
		eventLog.Tags = append(eventLog.Tags, BOOT_OPTIONS_PREFIX+*parsedEventLogEntry.EventDetails.OptionsFileName)
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_OPTION_EVENT_TYPE+DETAILS_SUFFIX)

	} else if parsedEventLogEntry.EventDetails.BootSecurityOption != nil {
		eventLog.TypeID = BOOT_SECURITY_OPTION_TYPE_ID
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.BootSecurityOption
		eventLog.Tags = append(eventLog.Tags, BOOT_SECURITY_OPTIONS_PREFIX+*parsedEventLogEntry.EventDetails.BootSecurityOption)
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_BOOT_SECURITY_OPTION_EVENT_TYPE+DETAILS_SUFFIX)
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
