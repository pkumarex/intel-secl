/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	fc "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type FlavorGroupStore struct {
	Store            *DataStore
	flavorPartsCache map[uuid.UUID]map[fc.FlavorPart]bool
	cacheLock        sync.RWMutex
}

func NewFlavorGroupStore(store *DataStore) *FlavorGroupStore {
	return &FlavorGroupStore{
		Store:            store,
		flavorPartsCache: make(map[uuid.UUID]map[fc.FlavorPart]bool),
	}
}

func (f *FlavorGroupStore) Create(fg *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("postgres/flavorgroup_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Create() Leaving")

	fg.ID = uuid.New()
	dbFlavorGroup := &flavorGroup{
		ID:                    fg.ID,
		Name:                  fg.Name,
		FlavorTypeMatchPolicy: PGFlavorMatchPolicies(fg.MatchPolicies),
	}

	if err := f.Store.Db.Create(&dbFlavorGroup).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:Create() failed to create Flavorgroup")
	}
	return fg, nil
}

func (f *FlavorGroupStore) Retrieve(flavorGroupId uuid.UUID) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("postgres/flavorgroup_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Retrieve() Leaving")

	fg := hvs.FlavorGroup{}
	row := f.Store.Db.Model(&flavorGroup{}).Where(&flavorGroup{ID: flavorGroupId}).Row()
	if err := row.Scan(&fg.ID, &fg.Name, (*PGFlavorMatchPolicies)(&fg.MatchPolicies)); err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:Retrieve() failed to scan record")
	}
	return &fg, nil
}

func (f *FlavorGroupStore) Search(fgFilter *models.FlavorGroupFilterCriteria) ([]hvs.FlavorGroup, error) {
	defaultLog.Trace("postgres/flavorgroup_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Search() Leaving")

	var err error
	if fgFilter != nil && fgFilter.FlavorId != nil {
		fgFilter.Ids, err = f.searchFlavorGroups(fgFilter.FlavorId)
		if err != nil {
			return nil, errors.New("postgres/flavorgroup_store:Search() Unexpected Error. " +
				"Error getting associated flavorgroups")
		}
		//If filter is only on the basis of flavor Id and no records are there then return
		if fgFilter.NameEqualTo == "" && fgFilter.NameContains == "" && len(fgFilter.Ids) == 0 {
			return []hvs.FlavorGroup{}, nil
		}
	}
	tx := buildFlavorGroupSearchQuery(f.Store.Db, fgFilter)

	if tx == nil {
		return nil, errors.New("postgres/flavorgroup_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in FlavorGroups Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	flavorgroupList := []hvs.FlavorGroup{}
	for rows.Next() {
		fg := hvs.FlavorGroup{}
		if err := rows.Scan(&fg.ID, &fg.Name, (*PGFlavorMatchPolicies)(&fg.MatchPolicies)); err != nil {
			return nil, errors.Wrap(err, "postgres/flavorgroup_store:Search() failed to scan record")
		}
		flavorgroupList = append(flavorgroupList, fg)
	}

	return flavorgroupList, nil
}

func (f *FlavorGroupStore) Delete(flavorGroupId uuid.UUID) error {
	defaultLog.Trace("postgres/flavorgroup_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Delete() Leaving")

	dbFlavorGroup := flavorGroup{
		ID: flavorGroupId,
	}
	if err := f.Store.Db.Delete(&dbFlavorGroup).Error; err != nil {
		return errors.Wrap(err, "postgres/flavorgroup_store:Delete() failed to delete Flavorgroup")
	}

	// remove cache entry for flavor parts with flavorgroup id if it exists
	f.removeFlavorTypesCacheEntry(flavorGroupId)
	return nil
}

// helper function to build the query object for a FlavorGroup search.
func buildFlavorGroupSearchQuery(tx *gorm.DB, fgFilter *models.FlavorGroupFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/flavorgroup_store:buildFlavorGroupSearchQuery() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:buildFlavorGroupSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&flavorGroup{})
	if fgFilter == nil {
		return tx
	}

	if len(fgFilter.Ids) > 0 {
		tx = tx.Where("id in (?)", fgFilter.Ids)
	} else if fgFilter.NameEqualTo != "" {
		tx = tx.Where("name = ?", fgFilter.NameEqualTo)
	} else if fgFilter.NameContains != "" {
		tx = tx.Where("name like ? ", "%"+fgFilter.NameContains+"%")
	}
	return tx
}

func (f *FlavorGroupStore) removeFlavorTypesCacheEntry(fgId uuid.UUID) {
	f.cacheLock.Lock()
	if _, exists := f.flavorPartsCache[fgId]; exists {
		delete(f.flavorPartsCache, fgId)
	}
	f.cacheLock.Unlock()
}

// AddFlavors creates a FlavorGroup-Flavor link
func (f *FlavorGroupStore) AddFlavors(fgId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavorgroup_store:AddFlavors() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:AddFlavors() Leaving")
	if len(fIds) <= 0 || fgId == uuid.Nil {
		return nil, errors.New("postgres/flavorgroup_store:AddFlavors()- invalid input : must have flavorId and flavorgroupId to associate flavorgroup with the flavor")
	}

	fgfValues := []string{}
	fgfValueArgs := []interface{}{}
	for _, fId := range fIds {
		fgfValues = append(fgfValues, "(?, ?)")
		fgfValueArgs = append(fgfValueArgs, fgId)
		fgfValueArgs = append(fgfValueArgs, fId)
	}
	insertQuery := fmt.Sprintf("INSERT INTO flavorgroup_flavor VALUES %s", strings.Join(fgfValues, ","))
	err := f.Store.Db.Model(flavorgroupFlavor{}).Exec(insertQuery, fgfValueArgs...).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:AddFlavors() failed to create flavorgroup-flavor association")
	}
	// remove cache entry if it exists as the entry is stale with addition of a flavor
	f.removeFlavorTypesCacheEntry(fgId)

	return fIds, nil
}

// RemoveFlavors deletes one or more FlavorGroup-Flavor links
func (f *FlavorGroupStore) RemoveFlavors(fgId uuid.UUID, fIds []uuid.UUID) error {
	defaultLog.Trace("postgres/flavorgroup_store:RemoveFlavors() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:RemoveFlavors() Leaving")

	if fgId == uuid.Nil && len(fIds) <= 0 {
		return errors.New("postgres/flavorgroup_store:RemoveFlavors()- invalid input : must have flavorId or flavorgroupId to delete flavorgroup-flavor association")
	}
	tx := f.Store.Db
	if fgId != uuid.Nil {
		tx = tx.Where("flavorgroup_id = ?", fgId)
	}

	if len(fIds) >= 1 {
		tx = tx.Where("flavor_id IN (?)", fIds)
	}

	if err := tx.Delete(&flavorgroupFlavor{}).Error; err != nil {
		return errors.Wrap(err, "postgres/flavorgroup_store:RemoveFlavors() failed to delete flavorgroup-flavor association")
	}

	// remove cache entry if it exists as the entry is stale with removal of the flavor
	f.removeFlavorTypesCacheEntry(fgId)

	return nil
}

// SearchFlavors returns a list of flavors linked to flavorgroup
func (f *FlavorGroupStore) SearchFlavors(fgId uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavorgroup_store:SearchFlavors() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:SearchFlavors() Leaving")

	// filter by flavorgroup id
	tx := f.Store.Db.Model(&flavorgroupFlavor{})
	tx = tx.Select("flavor_id").Where("flavorgroup_id = ?", fgId)
	if tx == nil {
		return nil, errors.New("postgres/flavorgroup_store:SearchFlavors() Unexpected Error. Could not build" +
			" a gorm query object in FlavorGroupsFlavors Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:SearchFlavors() failed to retrieve records from db")
	}
	defer rows.Close()

	flavorIds := []uuid.UUID{}

	for rows.Next() {
		flavorId := uuid.UUID{}
		if err := rows.Scan(&flavorId); err != nil {
			return nil, errors.Wrap(err, "postgres/flavorgroup_store:SearchFlavors() failed to scan record")
		}
		flavorIds = append(flavorIds, flavorId)
	}
	return flavorIds, nil
}

// RetrieveFlavor retrieves a single FlavorGroup-Flavor link
func (f *FlavorGroupStore) RetrieveFlavor(fgId uuid.UUID, fId uuid.UUID) (*hvs.FlavorgroupFlavorLink, error) {
	defaultLog.Trace("postgres/flavorgroup_store:RetrieveFlavor() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:RetrieveFlavor() Leaving")

	var result hvs.FlavorgroupFlavorLink

	row := f.Store.Db.Model(&flavorgroupFlavor{}).Where(&flavorgroupFlavor{FlavorgroupId: fgId, FlavorId: fId}).Row()
	if err := row.Scan(&result.FlavorGroupID, &result.FlavorID); err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:RetrieveFlavor() failed to scan record")
	}

	return &result, nil
}

// SearchHostsByFlavorGroup is used to fetch a list of hosts which are linked to the provided FlavorGroup
func (f *FlavorGroupStore) SearchHostsByFlavorGroup(fgID uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavorgroup_store:SearchHostsByFlavorGroups() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:SearchHostsByFlavorGroups() Leaving")

	rows, err := f.Store.Db.Model(&hostFlavorgroup{}).Select("host_id").Where(&hostFlavorgroup{FlavorgroupId: fgID}).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:SearchHostsByFlavorGroup() failed to retrieve records from db")
	}
	defer rows.Close()

	var hIDs []uuid.UUID
	for rows.Next() {
		var hId uuid.UUID
		if err := rows.Scan(&hId); err != nil {
			return nil, errors.Wrap(err, "postgres/flavorgroup_store:SearchHostsByFlavorGroup() failed to scan record")
		}
		hIDs = append(hIDs, hId)
	}

	return hIDs, nil
}

// searchFlavorGroups returns a list of flavorgroups linked to flavor
func (f *FlavorGroupStore) searchFlavorGroups(flavorId *uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavorgroup_store:searchFlavorGroups() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:searchFlavorGroups() Leaving")

	// filter by flavorgroup id
	tx := f.Store.Db.Model(&flavorgroupFlavor{})
	tx = tx.Select("flavorgroup_id").Where("flavor_id = ?", flavorId)
	if tx == nil {
		return nil, errors.New("postgres/flavorgroup_store:searchFlavorGroups() Unexpected Error. Could not build" +
			" a gorm query object in FlavorGroupsFlavors Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:searchFlavorGroups() failed to retrieve records from db")
	}
	defer rows.Close()

	flavorGroupIds := []uuid.UUID{}
	for rows.Next() {
		flavorGroupId := uuid.UUID{}
		if err := rows.Scan(&flavorGroupId); err != nil {
			return nil, errors.Wrap(err, "postgres/flavorgroup_store:searchFlavorGroups() failed to scan record")
		}
		flavorGroupIds = append(flavorGroupIds, flavorGroupId)
	}
	return flavorGroupIds, nil
}

// Returns different flavor types of flavors that are part of the flavor group. It is returned as a map
// It relies on the a cache entry - only if the cache entry does not exist, a database lookup is performed
func (f *FlavorGroupStore) GetFlavorTypesInFlavorGroup(fgId uuid.UUID) (map[fc.FlavorPart]bool, error) {
	defaultLog.Trace("postgres/flavorgroup_store:GetFlavorTypesInFlavorGroup() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:GetFlavorTypesInFlavorGroup() Leaving")

	// obtain a read lock before we check if an entry exists in the cache. Release the lock after reading in either
	// path. Cannot use defer RUnlock since we will have to modify the cache if an entry is not found.
	f.cacheLock.RLock()
	if flavorParts, exists := f.flavorPartsCache[fgId]; exists {
		f.cacheLock.RUnlock()
		return flavorParts, nil
	} else {
		// remove the read lock first.
		f.cacheLock.RUnlock()
		// create the map first.. the map itself might be empty if there are flavors in the flavorgroup

		var flavorParts []string
		err := f.Store.Db.Model(&flavor{}).Where("id in (select flavor_id from flavorgroup_flavor where flavorgroup_id = ?)", fgId).Pluck(("DISTINCT(flavor_part)"), &flavorParts).Error
		if err != nil {
			return nil, errors.Wrap(err, "postgres/host_store:GetFlavorTypesInFlavorGroup() failed to retrieve records from db")
		}
		fpMap := make(map[fc.FlavorPart]bool)
		for _, fp := range flavorParts {
			fpMap[fc.FlavorPart(fp)] = true
		}

		// take exclusive lock before making the cache entry
		f.cacheLock.Lock()
		f.flavorPartsCache[fgId] = fpMap
		f.cacheLock.Unlock()
		return fpMap, nil
	}

}
