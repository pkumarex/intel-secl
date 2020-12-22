/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	OsVMware string = "VMWARE ESXI"
	OsLinux  string = "LINUX"

	// Software Flavor Prefix
	DefaultSoftwareFlavorPrefix string = "ISecL_Default_Application_Flavor_v"
	DefaultWorkloadFlavorPrefix string = "ISecL_Default_Workload_Flavor_v"

	// TPM
	TPMVersion2 string = "2.0"

	Tpm   = "TPM"
	Txt   = "TXT"
	Cbnt  = "CBNT"
	Uefi  = "UEFI"
	Sboot = "SecureBootEnabled"

	//Pcr
	PcrClassNamePrefix = "com.intel.mtwilson.core.common.model.PcrSha"

	// Manifest / Measurement
	MeasurementTypeClassNamePrefix = "com.intel.mtwilson.core.common.model.MeasurementSha"
	IslMeasurementSchema           = "lib:wml:measurements:1.0"

	// ESXFlavor
	VMWareComponentName = "Vim25Api.HostTpmSoftwareComponentEventDetails"

	// HostInfo
	PCRBankSeparator = "_"

	// Timestamp format
	FlavorTimestampFormat   = "2006-01-02T15:04:05-0700"
	FlavorWoTimestampFormat = "2006-01-02T15:04:05.999999-07:00"
)
