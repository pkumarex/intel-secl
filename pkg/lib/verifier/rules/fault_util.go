/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

//
// This file contains utility functions that support a 'rules' ability to add 'faults'
// to a 'hvs.RuleResult'.
//

import (
	"fmt"
	"reflect"

	"github.com/google/uuid"
	faultsConst "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

func newPcrValueMissingFault(bank types.SHAAlgorithm, pcrIndex types.PcrIndex) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrValueMissing,
		Description: fmt.Sprintf("Host report does not include required PCR %d, bank %s", pcrIndex, bank),
		PcrIndex:    &pcrIndex,
	}
}

func newPcrValueMismatchFault(pcrIndex types.PcrIndex, PcrBank types.SHAAlgorithm, expectedPcr types.Pcr, expectedPcrLog types.PCRS, actualPcr types.Pcr) hvs.Fault {

	if !reflect.DeepEqual(expectedPcrLog, types.PCRS{}) {
		return hvs.Fault{
			Name:             faultsConst.FaultPcrValueMismatch + string(actualPcr.PcrBank),
			Description:      fmt.Sprintf("Host PCR %d of %s with value '%s' does not match expected value '%s'", pcrIndex, PcrBank, actualPcr.Value, expectedPcrLog.Measurement),
			PcrIndex:         &pcrIndex,
			PcrBank:          &PcrBank,
			ExpectedPcrValue: &expectedPcrLog.Measurement,
			ActualPcrValue:   &actualPcr.Value,
		}
	} else {
		return hvs.Fault{
			Name:             faultsConst.FaultPcrValueMismatch + string(actualPcr.PcrBank),
			Description:      fmt.Sprintf("Host PCR %d of %s with value '%s' does not match expected value '%s'", pcrIndex, PcrBank, actualPcr.Value, expectedPcr.Value),
			PcrIndex:         &pcrIndex,
			ExpectedPcrValue: &expectedPcr.Value,
			ActualPcrValue:   &actualPcr.Value,
		}
	}
}

func newPcrEventLogMissingExpectedEntries(eventLogEntry *types.EventLogEntry, pcrEventLogEntry *types.TpmEventLog) hvs.Fault {

	if pcrEventLogEntry != nil {
		pIndex := types.PcrIndex(pcrEventLogEntry.Pcr.Index)
		pBank := types.SHAAlgorithm(pcrEventLogEntry.Pcr.Bank)
		return hvs.Fault{
			Name:              faultsConst.FaultPcrEventLogMissingExpectedEntries,
			Description:       fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", pcrEventLogEntry.Pcr.Index, pcrEventLogEntry.Pcr.Bank, len(pcrEventLogEntry.TpmEvent)),
			PcrIndex:          &pIndex,
			PcrBank:           &pBank,
			MissingEventEntries: pcrEventLogEntry.TpmEvent,
		}
	} else {
		return hvs.Fault{
			Name:           faultsConst.FaultPcrEventLogMissingExpectedEntries,
			Description:    fmt.Sprintf("Module manifest for PCR %d missing %d expected entries", eventLogEntry.PcrIndex, len(eventLogEntry.EventLogs)),
			PcrIndex:       &eventLogEntry.PcrIndex,
			MissingEntries: eventLogEntry.EventLogs,
		}
	}
}

func newPcrEventLogMissingFault(pcrIndex types.PcrIndex, PcrBank types.SHAAlgorithm) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrEventLogMissing,
		Description: fmt.Sprintf("Host report does not include a PCR Event Log for PCR %d of %s value", pcrIndex, PcrBank),
		PcrIndex:    &pcrIndex,
		PcrBank:     &PcrBank,
	}
}

func newPcrEventLogContainsUnexpectedEntries(eventLogEntry *types.EventLogEntry, pcrEventLogEntry *types.TpmEventLog) hvs.Fault {

	if pcrEventLogEntry != nil {
		pIndex := types.PcrIndex(pcrEventLogEntry.Pcr.Index)
		pBank := types.SHAAlgorithm(pcrEventLogEntry.Pcr.Bank)
		return hvs.Fault{
			Name:                 faultsConst.FaultPcrEventLogContainsUnexpectedEntries,
			Description:          fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", pcrEventLogEntry.Pcr.Index, pcrEventLogEntry.Pcr.Bank, len(pcrEventLogEntry.TpmEvent)),
			PcrIndex:             &pIndex,
			PcrBank:              &pBank,
			UnexpectedEventEntries: pcrEventLogEntry.TpmEvent,
		}
	} else {
		return hvs.Fault{
			Name:              faultsConst.FaultPcrEventLogContainsUnexpectedEntries,
			Description:       fmt.Sprintf("Module manifest for PCR %d contains %d unexpected entries", eventLogEntry.PcrIndex, len(eventLogEntry.EventLogs)),
			PcrIndex:          &eventLogEntry.PcrIndex,
			UnexpectedEntries: eventLogEntry.EventLogs,
		}
	}
}

func newXmlEventLogMissingFault(flavorId uuid.UUID) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultXmlMeasurementLogMissing,
		Description: fmt.Sprintf("Host report does not contain XML Measurement log for flavor %s.", flavorId),
	}
}

func newXmlMeasurementValueMismatch(expectedCumulativeHash string, actualCumulativeHash string) hvs.Fault {
	return hvs.Fault{
		Name:          faultsConst.FaultXmlMeasurementValueMismatch,
		Description:   fmt.Sprintf("Host XML measurement log final hash with value '%s' does not match expected value '%s'", actualCumulativeHash, expectedCumulativeHash),
		ExpectedValue: &expectedCumulativeHash,
		ActualValue:   &actualCumulativeHash,
	}
}

func newFlavorSignatureVerificationFailed(flavorId uuid.UUID) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultFlavorSignatureVerificationFailed,
		Description: fmt.Sprintf("Signature verification failed for flavor with id %s", flavorId),
	}
}

func newXmlMeasurementLogInvalidFault() hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultXmlMeasurementLogInvalid,
		Description: "Unable to parse one of the measurements present in HostManifest",
	}
}

func newPcrManifestMissingFault() hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrManifestMissing,
		Description: "Host report does not include a PCR Manifest",
	}
}
