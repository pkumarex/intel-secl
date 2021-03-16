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
	StartupLocalityTag   = "StartupLocality3"
	StartupLocalityEvent = "EV_NO_ACTION"
)

const (
	PCR_INDEX_PREFIX = "pcr_"
)

type Pcr struct {
	Index   PcrIndex     `json:"index"`
	Value   string       `json:"value"`
	PcrBank SHAAlgorithm `json:"pcr_bank"`
}

type EventLog struct {
	TypeID      string   `json:"type_id"`   //oneof-required
	TypeName    string   `json:"type_name"` //oneof-required
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"` //required
}

type eventLogKeyAttr struct {
	TypeID      string `json:"type_id"`
	Measurement string `json:"measurement"`
}

type TpmEventLog struct {
	Pcr      PCR        `json:"pcr"`
	TpmEvent []EventLog `json:"tpm_events"`
}

//PCR - To store PCR index with respective PCR bank.
type PCR struct {
	// Valid PCR index is from 0 to 23.
	Index int `json:"index"`
	// Valid PCR banks are SHA1, SHA256, SHA384 and SHA512.
	Bank string `json:"bank"`
}
type PCRS struct {
	PCR              PCR            `json:"pcr"`         //required
	Measurement      string         `json:"measurement"` //required
	PCRMatches       bool           `json:"pcr_matches,omitempty"`
	EventlogEqual    *EventLogEqual `json:"eventlog_equals,omitempty"`
	EventlogIncludes []EventLog     `json:"eventlog_includes,omitempty"`
}

type EventLogEqual struct {
	Events      []EventLog `json:"events,omitempty"`
	ExcludeTags []string   `json:"exclude_tags,omitempty"`
}

type PcrEventLogMap struct {
	Sha1EventLogs   []TpmEventLog `json:"SHA1"`
	Sha256EventLogs []TpmEventLog `json:"SHA256"`
}
type PcrManifest struct {
	Sha1Pcrs       []Pcr          `json:"sha1pcrs"`
	Sha256Pcrs     []Pcr          `json:"sha2pcrs"`
	PcrEventLogMap PcrEventLogMap `json:"pcr_event_log_map"`
}

type PcrIndex int

func (p PCRS) EqualsWithoutValue(pcr PCRS) bool {
	return reflect.DeepEqual(p.PCR.Index, pcr.PCR.Index) && reflect.DeepEqual(p.PCR.Bank, pcr.PCR.Bank)
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

	switch pcrBank {
	case SHA1:
		for _, pcr := range pcrManifest.Sha1Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	case SHA256:
		for _, pcr := range pcrManifest.Sha256Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	default:
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
func (pcrEventLogMap *PcrEventLogMap) GetEventLogNew(pcrBank string, pcrIndex int) ([]EventLog, int, string, error) {
	var eventLog []EventLog
	var pIndex int
	var bank string

	switch SHAAlgorithm(pcrBank) {
	case SHA1:
		for _, entry := range pcrEventLogMap.Sha1EventLogs {
			if entry.Pcr.Index == pcrIndex {
				eventLog = entry.TpmEvent
				pIndex = entry.Pcr.Index
				bank = entry.Pcr.Bank
				break
			}
		}
	case SHA256:
		for _, entry := range pcrEventLogMap.Sha256EventLogs {
			if entry.Pcr.Index == pcrIndex {
				eventLog = entry.TpmEvent
				pIndex = entry.Pcr.Index
				bank = entry.Pcr.Bank
				break
			}
		}
	default:
		return nil, 0, "", errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return eventLog, pIndex, bank, nil
}

// Provided an EventLogEntry that contains an array of EventLogs, this function
// will return a new EventLogEntry that contains the events that existed in
// the original ('eventLogEntry') but not in 'eventsToSubtract'.  Returns an error
// if the bank/index of 'eventLogEntry' and 'eventsToSubtract' do not match.
// Note: 'eventLogEntry' and 'eventsToSubract' are not altered.
func (eventLogEntry *TpmEventLog) Subtract(eventsToSubtract *TpmEventLog) (*TpmEventLog, *TpmEventLog, error) {
	if eventLogEntry.Pcr.Bank != eventsToSubtract.Pcr.Bank {
		return nil, nil, errors.Errorf("The PCR banks do not match: '%s' != '%s'", eventLogEntry.Pcr.Bank, eventsToSubtract.Pcr.Bank)
	}

	if eventLogEntry.Pcr.Index != eventsToSubtract.Pcr.Index {
		return nil, nil, errors.Errorf("The PCR indexes do not match: '%d' != '%d'", eventLogEntry.Pcr.Index, eventsToSubtract.Pcr.Index)
	}

	// build a new EventLogEntry that will be populated by the event log entries
	// in the source less those 'eventsToSubtract'.
	subtractedEvents := TpmEventLog{
		Pcr: PCR{
			Bank:  eventLogEntry.Pcr.Bank,
			Index: eventLogEntry.Pcr.Index,
		},
	}

	mismatchedEvents := TpmEventLog{
		Pcr: PCR{
			Bank:  eventLogEntry.Pcr.Bank,
			Index: eventLogEntry.Pcr.Index,
		},
	}

	eventsToSubtractMap := make(map[eventLogKeyAttr]EventLog)
	for _, eventLog := range eventsToSubtract.TpmEvent {
		compareInfo := eventLogKeyAttr{
			Measurement: eventLog.Measurement,
			TypeID:      eventLog.TypeID,
		}

		eventLogData := EventLog{
			Tags:     eventLog.Tags,
			TypeName: eventLog.TypeName,
		}
		eventsToSubtractMap[compareInfo] = eventLogData
	}

	//Compare event log entries value (measurement and TypeID) .If mismatched,raise faults
	//else proceed to compare type_name and tags.
	//If these fields are mismatched,then add the mismatch entry details to report(not a fault)
	misMatch := false
	for _, eventLog := range eventLogEntry.TpmEvent {
		compareInfo := eventLogKeyAttr{
			Measurement: eventLog.Measurement,
			TypeID:      eventLog.TypeID,
		}
		if events, ok := eventsToSubtractMap[compareInfo]; ok {

			if len(events.TypeName) != 0 && len(eventLog.TypeName) != 0 {
				if events.TypeName != eventLog.TypeName {
					misMatch = true

				}
			}
			if events.Tags != nil && len(events.Tags) != 0 && len(eventLog.Tags) != 0 {
				if !reflect.DeepEqual(events.Tags, eventLog.Tags) {
					misMatch = true
				}
			}

			if misMatch {
				mismatchedEvents.TpmEvent = append(mismatchedEvents.TpmEvent, eventLog)
				misMatch = false
			}
		} else {
			subtractedEvents.TpmEvent = append(subtractedEvents.TpmEvent, eventLog)
		}
	}

	return &subtractedEvents, &mismatchedEvents, nil
}

// Returns the string value of the "cumulative" hash of the
// an event log.
func (eventLogEntry *TpmEventLog) Replay() (string, error) {
	//get the cumulative hash based on the pcr bank
	cumulativeHash, err := getCumulativeHash(SHAAlgorithm(eventLogEntry.Pcr.Bank))
	if err != nil {
		return "", err
	}

	// use the first EV_NO_ACTION/"StartupLocality" event to send the cumualtive hash
	if eventLogEntry.Pcr.Index == 0 && eventLogEntry.TpmEvent[0].TypeName == StartupLocalityEvent &&
		eventLogEntry.TpmEvent[0].Tags[0] == StartupLocalityTag {
		cumulativeHash[len(cumulativeHash)-1] = 0x3
	}

	for i, eventLog := range eventLogEntry.TpmEvent {
		//if the event is EV_NO_ACTION, skip from summing the hash
		if eventLog.TypeName == StartupLocalityEvent {
			continue
		}
		//get the respective hash based on the pcr bank
		hash := getHash(SHAAlgorithm(eventLogEntry.Pcr.Bank))

		eventHash, err := hex.DecodeString(eventLog.Measurement)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to decode event log %d using hex string '%s'", i, eventLog.Measurement)
		}

		hash.Write(cumulativeHash)
		hash.Write(eventHash)
		cumulativeHash = hash.Sum(nil)
	}

	cumulativeHashString := hex.EncodeToString(cumulativeHash)
	return cumulativeHashString, nil
}

// GetEventLog returns the EventLogs for a specific PcrBank/PcrIndex, as per latest hostmanifest
func (pcrManifest *PcrManifest) GetEventLog(pcrBank SHAAlgorithm, pcrIndex PcrIndex) ([]EventLog, error) {
	pI := int(pcrIndex)

	switch pcrBank {
	case "SHA1":
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha1EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	case "SHA256":
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha256EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	default:
		return nil, fmt.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return nil, fmt.Errorf("Invalid PcrIndex %d", pcrIndex)
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

//getHash method returns the hash based on the pcr bank
func getHash(pcrBank SHAAlgorithm) hash.Hash {
	var hash hash.Hash

	switch pcrBank {
	case SHA1:
		hash = sha1.New()
	case SHA256:
		hash = sha256.New()
	case SHA384:
		hash = sha512.New384()
	case SHA512:
		hash = sha512.New()
	}

	return hash
}

//getCumulativeHash method returns the cumulative hash based on the pcr bank
func getCumulativeHash(pcrBank SHAAlgorithm) ([]byte, error) {
	var cumulativeHash []byte

	switch pcrBank {
	case SHA1:
		cumulativeHash = make([]byte, sha1.Size)
	case SHA256:
		cumulativeHash = make([]byte, sha256.Size)
	case SHA384:
		cumulativeHash = make([]byte, sha512.Size384)
	case SHA512:
		cumulativeHash = make([]byte, sha512.Size)
	default:
		return nil, errors.Errorf("Invalid sha algorithm '%s'", pcrBank)
	}

	return cumulativeHash, nil
}
