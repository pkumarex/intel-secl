/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const (
	PCR_INDEX_PREFIX = "pcr_"
)

type Pcr struct {
	DigestType string       `json:"digest_type"`
	Index      PcrIndex     `json:"index"`
	Value      string       `json:"value"`
	PcrBank    SHAAlgorithm `json:"pcr_bank"`
}

type EventLog struct {
	DigestType string            `json:"digest_type"`
	Value      string            `json:"value"`
	Label      string            `json:"label"`
	Info       map[string]string `json:"info"`
}

type EventLogCriteria struct {
	TypeID      string   `json:"type_id"`   //oneof-required
	TypeName    string   `json:"type_name"` //oneof-required
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"` //required
}

type EventLogEntry struct {
	PcrIndex  PcrIndex     `json:"pcr_index"`
	EventLogs []EventLog   `json:"event_log"`
	PcrBank   SHAAlgorithm `json:"pcr_bank"`
}

type EventLogEntryFC struct {
	Pcr      PCR                `json:"pcr"`
	TpmEvent []EventLogCriteria `json:"tpm_events"`
}

type PCR struct {
	Index int    `json:"index"`
	Bank  string `json:"bank"`
}

type PCRS struct {
	PCR              PCR                `json:"pcr"`         //required
	Measurement      string             `json:"measurement"` //required
	PCRMatches       bool               `json:"pcr_matches,omitempty"`
	EventlogEqual    *EventLogEqual     `json:"eventlog_equals,omitempty"`
	EventlogIncludes []EventLogCriteria `json:"eventlog_includes,omitempty"`
}

type EventLogEqual struct {
	Events      []EventLogCriteria `json:"events,omitempty"`
	ExcludeTags []string           `json:"exclude_tags,omitempty"`
}

type PcrEventLogMap struct {
	Sha1EventLogs   []EventLogEntry `json:"SHA1"`
	Sha256EventLogs []EventLogEntry `json:"SHA256"`
}

type PcrEventLogMapFC struct {
	Sha1EventLogs   []EventLogEntryFC `json:"SHA1"`
	Sha256EventLogs []EventLogEntryFC `json:"SHA256"`
}
type PcrManifest struct {
	Sha1Pcrs          []Pcr            `json:"sha1pcrs"`
	Sha256Pcrs        []Pcr            `json:"sha2pcrs"`
	PcrEventLogMap    PcrEventLogMap   `json:"pcr_event_log_map"`
	PcrEventLogMapNew PcrEventLogMapFC `json:"pcr_event_log_map_new"`
}

type PcrIndex int

func (p Pcr) EqualsWithoutValue(pcr Pcr) bool {
	return p.DigestType == pcr.DigestType && reflect.DeepEqual(p.Index, pcr.Index) && reflect.DeepEqual(p.PcrBank, pcr.PcrBank)
}

// String returns the string representation of the PcrIndex
func (p PcrIndex) String() string {
	return fmt.Sprintf("pcr_%d", p)
}

const (
	PCR0 PcrIndex = iota
	PCR1
	PCR2
	PCR3
	PCR4
	PCR5
	PCR6
	PCR7
	PCR8
	PCR9
	PCR10
	PCR11
	PCR12
	PCR13
	PCR14
	PCR15
	PCR16
	PCR17
	PCR18
	PCR19
	PCR20
	PCR21
	PCR22
	PCR23
	INVALID_INDEX = -1
)

// Convert the integer value of PcrIndex into "pcr_N" string (for xml serialization)
func (pcrIndex PcrIndex) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	xmlValue := fmt.Sprintf("pcr_%d", int(pcrIndex))
	return e.EncodeElement(xmlValue, start)
}

// Convert the xml string value "pcr_N" to PcrIndex
func (pcrIndex *PcrIndex) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var xmlValue string
	err := d.DecodeElement(&xmlValue, &start)
	if err != nil {
		return errors.Wrap(err, "Could not decode PcrIndex from XML")
	}

	index, err := GetPcrIndexFromString(xmlValue)
	if err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from XML")
	}

	*pcrIndex = index
	return nil
}

// Convert the integer value of PcrIndex into "pcr_N" string (for json serialization)
func (pcrIndex PcrIndex) MarshalJSON() ([]byte, error) {
	jsonValue := fmt.Sprintf("pcr_%d", int(pcrIndex))
	return json.Marshal(jsonValue)
}

// Convert the json string value "pcr_N" to PcrIndex
func (pcrIndex *PcrIndex) UnmarshalJSON(b []byte) error {
	var jsonValue string
	if err := json.Unmarshal(b, &jsonValue); err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from JSON")
	}

	index, err := GetPcrIndexFromString(jsonValue)
	if err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from JSON")
	}

	*pcrIndex = index
	return nil
}

type SHAAlgorithm string

const (
	SHA1    SHAAlgorithm = "SHA1"
	SHA256  SHAAlgorithm = "SHA256"
	SHA384  SHAAlgorithm = "SHA384"
	SHA512  SHAAlgorithm = "SHA512"
	UNKNOWN SHAAlgorithm = "unknown"
)

func GetSHAAlgorithm(algorithm string) (SHAAlgorithm, error) {
	switch algorithm {
	case string(SHA1):
		return SHA1, nil
	case string(SHA256):
		return SHA256, nil
	case string(SHA384):
		return SHA384, nil
	case string(SHA512):
		return SHA512, nil
	}

	return UNKNOWN, errors.Errorf("Could not retrieve SHA from value '%s'", algorithm)
}

// Parses a string value in either integer form (i.e. "8") or "pcr_N"
// where 'N' is the integer value between 0 and 23.  Ex. "pcr_7".  Returns
// an error if the string is not in the correct format or if the index
// value is not between 0 and 23.
func GetPcrIndexFromString(stringValue string) (PcrIndex, error) {

	intString := stringValue

	if strings.Contains(intString, PCR_INDEX_PREFIX) {
		intString = strings.ReplaceAll(stringValue, PCR_INDEX_PREFIX, "")
	}

	intValue, err := strconv.ParseInt(intString, 0, 64)
	if err != nil {
		return INVALID_INDEX, errors.Wrapf(err, "Could not unmarshal PcrIndex from string value '%s'", stringValue)
	}

	if intValue < int64(PCR0) || intValue > int64(PCR23) {
		return INVALID_INDEX, errors.Errorf("Invalid PCR index %d", intValue)
	}

	return PcrIndex(intValue), nil
}

// Finds the Pcr in a PcrManifest provided the pcrBank and index.  Returns
// null if not found.  Returns an error if the pcrBank is not supported
// by intel-secl (currently supports SHA1 and SHA256).
func (pcrManifest *PcrManifest) GetPcrValue(pcrBank SHAAlgorithm, pcrIndex PcrIndex) (*Pcr, error) {
	// TODO: Is this the right data model for the PcrManifest?  Two things...
	// - Flavor API returns a map[bank]map[pcrindex]
	// - Finding the PCR by bank/index is a linear search.
	var pcrValue *Pcr

	if pcrBank == SHA1 {
		for _, pcr := range pcrManifest.Sha1Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	} else if pcrBank == SHA256 {
		for _, pcr := range pcrManifest.Sha256Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	} else {
		return nil, errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return pcrValue, nil
}

// Utility function that uses GetPcrValue but also returns an error if
// the Pcr was not found.
func (pcrManifest *PcrManifest) GetRequiredPcrValue(bank SHAAlgorithm, pcrIndex PcrIndex) (*Pcr, error) {
	pcrValue, err := pcrManifest.GetPcrValue(bank, pcrIndex)
	if err != nil {
		return nil, err
	}

	if pcrValue == nil {
		return nil, errors.Errorf("Could not retrive PCR at bank '%s', index %d", bank, pcrIndex)
	}

	return pcrValue, nil
}

// IsEmpty returns true if both the Sha1Pcrs and Sha256Pcrs
// are empty.
func (pcrManifest *PcrManifest) IsEmpty() bool {
	return len(pcrManifest.Sha1Pcrs) == 0 && len(pcrManifest.Sha256Pcrs) == 0
}

// Finds the EventLogEntry in a PcrEventLogMap provided the pcrBank and index.  Returns
// null if not found.  Returns an error if the pcrBank is not supported
// by intel-secl (currently supports SHA1 and SHA256).
func (pcrEventLogMap *PcrEventLogMap) GetEventLog(pcrBank SHAAlgorithm, pcrIndex PcrIndex) (*EventLogEntry, error) {

	var eventLogEntry *EventLogEntry

	if pcrBank == SHA1 {
		for _, entry := range pcrEventLogMap.Sha1EventLogs {
			if entry.PcrIndex == pcrIndex {
				eventLogEntry = &entry
				break
			}
		}
	} else if pcrBank == SHA256 {
		for _, entry := range pcrEventLogMap.Sha256EventLogs {
			if entry.PcrIndex == pcrIndex {
				eventLogEntry = &entry
				break
			}
		}
	} else {
		return nil, errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return eventLogEntry, nil
}

// Provided an EventLogEntry that contains an array of EventLogs, this function
// will return a new EventLogEntry that contains the events that existed in
// the original ('eventLogEntry') but not in 'eventsToSubtract'.  Returns an error
// if the bank/index of 'eventLogEntry' and 'eventsToSubtract' do not match.
// Note: 'eventLogEntry' and 'eventsToSubract' are not altered.
func (eventLogEntry *EventLogEntry) Subtract(eventsToSubtract *EventLogEntry) (*EventLogEntry, error) {

	if eventLogEntry.PcrBank != eventsToSubtract.PcrBank {
		return nil, errors.Errorf("The PCR banks do not match: '%s' != '%s'", eventLogEntry.PcrBank, eventsToSubtract.PcrBank)
	}

	if eventLogEntry.PcrIndex != eventsToSubtract.PcrIndex {
		return nil, errors.Errorf("The PCR indexes do not match: '%d' != '%d'", eventLogEntry.PcrIndex, eventsToSubtract.PcrIndex)
	}

	// build a new EventLogEntry that will be populated by the event log entries
	// in the source less those 'eventsToSubtract'.
	difference := EventLogEntry{
		PcrBank:  eventLogEntry.PcrBank,
		PcrIndex: eventLogEntry.PcrIndex,
	}

	index := make(map[string]int)
	for i, eventLog := range eventsToSubtract.EventLogs {
		index[eventLog.Value] = i
	}

	for _, eventLog := range eventLogEntry.EventLogs {
		if _, ok := index[eventLog.Value]; !ok {
			difference.EventLogs = append(difference.EventLogs, eventLog)
		}
	}

	return &difference, nil
}

// Returns the string value of the "cumulative" hash of the
// an event log.
func (eventLogEntry *EventLogEntry) Replay() (string, error) {

	var cumulativeHash []byte

	if eventLogEntry.PcrBank == SHA1 {
		cumulativeHash = make([]byte, sha1.Size)
	} else if eventLogEntry.PcrBank == SHA256 {
		cumulativeHash = make([]byte, sha256.Size)
	} else if eventLogEntry.PcrBank == SHA384 {
		cumulativeHash = make([]byte, sha512.Size384)
	} else if eventLogEntry.PcrBank == SHA512 {
		cumulativeHash = make([]byte, sha512.Size)
	} else {
		return "", errors.Errorf("Invalid sha algorithm '%s'", eventLogEntry.PcrBank)
	}

	for i, eventLog := range eventLogEntry.EventLogs {
		var hash hash.Hash
		if eventLogEntry.PcrBank == SHA1 {
			hash = sha1.New()
		} else if eventLogEntry.PcrBank == SHA256 {
			hash = sha256.New()
		} else if eventLogEntry.PcrBank == SHA384 {
			hash = sha512.New384()
		} else if eventLogEntry.PcrBank == SHA512 {
			hash = sha512.New()
		}

		eventHash, err := hex.DecodeString(eventLog.Value)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to decode event log %d using hex string '%s'", i, eventLog.Value)
		}

		_, err = hash.Write(cumulativeHash)
		if err != nil {
			return "", errors.Wrap(err, "Error writing cumulative hash")
		}
		_, err = hash.Write(eventHash)
		if err != nil {
			return "", errors.Wrap(err, "Error writing event hash")
		}
		cumulativeHash = hash.Sum(nil)
	}

	cumulativeHashString := hex.EncodeToString(cumulativeHash)
	return cumulativeHashString, nil
}

// GetPcrEventLog returns the EventLogs for a specific PcrBank/PcrIndex
func (pcrManifest *PcrManifest) GetPcrEventLog(pcrBank SHAAlgorithm, pcrIndex PcrIndex) ([]EventLog, error) {

	pI := PcrIndex(pcrIndex)
	if pcrBank == SHA1 {
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha1EventLogs {
			if eventLogEntry.PcrIndex == pI {
				return eventLogEntry.EventLogs, nil
			}
		}
	} else if pcrBank == SHA256 {
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha256EventLogs {
			if eventLogEntry.PcrIndex == pI {
				return eventLogEntry.EventLogs, nil
			}
		}
	} else {
		return nil, fmt.Errorf("Unsupported sha algorithm %s", pcrBank)
	}
	return nil, fmt.Errorf("Invalid PcrIndex %d", pcrIndex)
}

// GetPcrEventLogNew returns the EventLogs for a specific PcrBank/PcrIndex, as per latest hostmanifest
func (pcrManifest *PcrManifest) GetPcrEventLogNew(pcrBank SHAAlgorithm, pcrIndex PcrIndex) ([]EventLogCriteria, error) {

	pI := int(pcrIndex)
	if pcrBank == "SHA1" {
		for _, eventLogEntry := range pcrManifest.PcrEventLogMapNew.Sha1EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	} else if pcrBank == "SHA256" {
		for _, eventLogEntry := range pcrManifest.PcrEventLogMapNew.Sha256EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	} else {
		return nil, fmt.Errorf("Unsupported sha algorithm %s", pcrBank)
	}
	return nil, fmt.Errorf("Invalid PcrIndex %d", pcrIndex)
}

func (pcrManifest *PcrManifest) GetPcrValueForLinux(pcrBank string, pcrIndex int) (*Pcr, error) {
	// TODO: Is this the right data model for the PcrManifest?  Two things...
	// - Flavor API returns a map[bank]map[pcrindex]
	// - Finding the PCR by bank/index is a linear search.
	var pcrValue *Pcr
	pcrIndexString := "pcr_" + strconv.Itoa(pcrIndex)

	if pcrBank == "SHA1" {
		for _, pcr := range pcrManifest.Sha1Pcrs {
			if pcr.Index.String() == pcrIndexString {
				pcrValue = &pcr
				break
			}
		}
	} else if pcrBank == "SHA256" {
		for _, pcr := range pcrManifest.Sha256Pcrs {
			if pcr.Index.String() == pcrIndexString {
				pcrValue = &pcr
				break
			}
		}
	} else {
		return nil, errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return pcrValue, nil
}

// GetPcrBanks returns the list of banks currently supported by the PcrManifest
func (pcrManifest *PcrManifest) GetPcrBanks() []SHAAlgorithm {
	var bankList []SHAAlgorithm
	// check if each known digest algorithm is present and return
	if len(pcrManifest.Sha1Pcrs) > 0 {
		bankList = append(bankList, SHA1)
	}
	// check if each known digest algorithm is present and return
	if len(pcrManifest.Sha256Pcrs) > 0 {
		bankList = append(bankList, SHA256)
	}
	return bankList
}

type c interface {
	GetPcrBanks() []SHAAlgorithm
}
