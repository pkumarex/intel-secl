/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"reflect"
	"strings"
)

type HostStore struct {
	Store *DataStore
}

func NewHostStore(store *DataStore) *HostStore {
	return &HostStore{store}
}

func (hs *HostStore) Create(h *hvs.Host) (*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Create() Entering")
	defer defaultLog.Trace("postgres/host_store:Create() Leaving")

	h.Id = uuid.New()
	dbHost := host{
		Id:               h.Id,
		Name:             h.HostName,
		Description:      h.Description,
		ConnectionString: h.ConnectionString,
	}

	if h.HardwareUuid != nil {
		dbHost.HardwareUuid = models.NewHwUUID(*h.HardwareUuid)
	}

	if err := hs.Store.Db.Create(&dbHost).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:Create() failed to create Host")
	}
	return h, nil
}

func (hs *HostStore) Retrieve(id uuid.UUID) (*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/host_store:Retrieve() Leaving")

	h := hvs.Host{}
	row := hs.Store.Db.Model(&host{}).Where(&host{Id: id}).Row()
	if err := row.Scan(&h.Id, &h.HostName, &h.Description, &h.ConnectionString, &h.HardwareUuid); err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:Retrieve() failed to scan record")
	}
	return &h, nil
}

func (hs *HostStore) Update(h *hvs.Host) error {
	defaultLog.Trace("postgres/host_store:Update() Entering")
	defer defaultLog.Trace("postgres/host_store:Update() Leaving")

	dbHost := host{
		Id:               h.Id,
		Name:             h.HostName,
		Description:      h.Description,
		ConnectionString: h.ConnectionString,
	}

	if h.HardwareUuid != nil {
		dbHost.HardwareUuid = models.NewHwUUID(*h.HardwareUuid)
	}

	if db := hs.Store.Db.Model(&dbHost).Updates(&dbHost); db.Error != nil || db.RowsAffected != 1 {
		if db.Error != nil {
			return errors.Wrap(db.Error, "postgres/host_store:Update() failed to update Host  "+dbHost.Id.String())
		} else {
			return errors.New("postgres/host_store:Update() - no rows affected - Record not found = id :  " + dbHost.Id.String())
		}
	}
	return nil
}

func (hs *HostStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:Delete() Entering")
	defer defaultLog.Trace("postgres/host_store:Delete() Leaving")

	if err := hs.Store.Db.Delete(&host{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:Delete() failed to delete Host")
	}
	return nil
}

func (hs *HostStore) DeleteByHostName(hostName string) error {
	defaultLog.Trace("postgres/host_store:DeleteByHostName() Entering")
	defer defaultLog.Trace("postgres/host_store:DeleteByHostName() Leaving")

	if err := hs.Store.Db.Where("name=?", hostName).Delete(&host{}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:DeleteByHostName() failed to delete Host")
	}
	return nil
}

func (hs *HostStore) Search(criteria *models.HostFilterCriteria) ([]*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Search() Entering")
	defer defaultLog.Trace("postgres/host_store:Search() Leaving")

	tx := buildHostSearchQuery(hs.Store.Db, criteria)
	if tx == nil {
		return nil, errors.New("postgres/host_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	hosts := []*hvs.Host{}
	for rows.Next() {
		host := hvs.Host{}
		if err := rows.Scan(&host.Id, &host.HostName, &host.Description, &host.ConnectionString, &host.HardwareUuid); err != nil {
			return nil, errors.Wrap(err, "postgres/host_store:Search() failed to scan record")
		}
		hosts = append(hosts, &host)
	}
	return hosts, nil
}

// helper function to build the query object for a Host search.
func buildHostSearchQuery(tx *gorm.DB, criteria *models.HostFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/host_store:buildHostSearchQuery() Entering")
	defer defaultLog.Trace("postgres/host_store:buildHostSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&host{})
	if criteria == nil || reflect.DeepEqual(*criteria, models.HostFilterCriteria{}) {
		return tx
	}

	if criteria.Id != uuid.Nil {
		tx = tx.Where("id = ?", criteria.Id)
	} else if criteria.NameEqualTo != "" {
		tx = tx.Where("name = ?", criteria.NameEqualTo)
	} else if criteria.NameContains != "" {
		tx = tx.Where("name like ? ", "%"+criteria.NameContains+"%")
	} else if criteria.HostHardwareId != uuid.Nil {
		tx = tx.Where("hardware_uuid = ?", criteria.HostHardwareId)
	} else if criteria.IdList != nil {
		tx = tx.Where("id IN (?)", criteria.IdList)
	}

	return tx
}

func (hs *HostStore) AddFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:AddFlavorgroups() Entering")
	defer defaultLog.Trace("postgres/host_store:AddFlavorgroups() Leaving")

	var hfgValues []string
	var hfgValueArgs []interface{}
	for _, fgId := range fgIds {
		hfgValues = append(hfgValues, "(?, ?)")
		hfgValueArgs = append(hfgValueArgs, hId)
		hfgValueArgs = append(hfgValueArgs, fgId)
	}

	insertQuery := fmt.Sprintf("INSERT INTO host_flavorgroup VALUES %s", strings.Join(hfgValues, ","))
	err := hs.Store.Db.Model(hostFlavorgroup{}).Exec(insertQuery, hfgValueArgs...).Error
	if err != nil {
		return errors.Wrap(err, "postgres/host_store:AddFlavorgroups() failed to create Host Flavorgroup associations")
	}
	return nil
}

func (hs *HostStore) RetrieveFlavorgroup(hId uuid.UUID, fgId uuid.UUID) (*hvs.HostFlavorgroup, error) {
	defaultLog.Trace("postgres/host_store:RetrieveFlavorgroup() Entering")
	defer defaultLog.Trace("postgres/host_store:RetrieveFlavorgroup() Leaving")

	hf := hvs.HostFlavorgroup{}
	row := hs.Store.Db.Model(&hostFlavorgroup{}).Where(&hostFlavorgroup{HostId: hId, FlavorgroupId: fgId}).Row()
	if err := row.Scan(&hf.HostId, &hf.FlavorgroupId); err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:RetrieveFlavorgroup() failed to scan record")
	}
	return &hf, nil
}

func (hs *HostStore) RemoveFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:RemoveFlavorgroups() Entering")
	defer defaultLog.Trace("postgres/host_store:RemoveFlavorgroups() Leaving")

	tx := hs.Store.Db
	if hId != uuid.Nil {
		tx = tx.Where("host_id = ?", hId)
	}

	if len(fgIds) >= 1 {
		tx = tx.Where("flavorgroup_id IN (?)", fgIds)
	}

	if err := tx.Delete(&hostFlavorgroup{}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:RemoveFlavorgroups() failed to delete Host Flavorgroup association")
	}
	return nil
}

func (hs *HostStore) SearchFlavorgroups(hId uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:SearchFlavorgroups() Entering")
	defer defaultLog.Trace("postgres/host_store:SearchFlavorgroups() Leaving")

	rows, err := hs.Store.Db.Model(&hostFlavorgroup{}).Select("flavorgroup_id").Where(&hostFlavorgroup{HostId: hId}).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:SearchFlavorgroups() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	var fgIds []uuid.UUID
	for rows.Next() {
		var fgId uuid.UUID
		if err := rows.Scan(&fgId); err != nil {
			return nil, errors.Wrap(err, "postgres/host_store:SearchFlavorgroups() failed to scan record")
		}
		fgIds = append(fgIds, fgId)
	}
	return fgIds, nil
}

// create trust cache
func (hs *HostStore) AddTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:AddTrustCacheFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:AddTrustCacheFlavors() Leaving")
	if len(fIds) <= 0 || hId == uuid.Nil {
		return nil, errors.New("postgres/host_store:AddTrustCacheFlavors()- invalid input : must have flavorId and hostId to create the trust cache")
	}

	trustCacheValues := []string{}
	trustCacheValueArgs := []interface{}{}
	for _, fId := range fIds {
		trustCacheValues = append(trustCacheValues, "(?, ?)")
		trustCacheValueArgs = append(trustCacheValueArgs, fId)
		trustCacheValueArgs = append(trustCacheValueArgs, hId)
	}

	insertQuery := fmt.Sprintf("INSERT INTO trust_cache VALUES %s on conflict (flavor_id, host_id) do nothing", strings.Join(trustCacheValues, ","))
	err := hs.Store.Db.Model(trustCache{}).Exec(insertQuery, trustCacheValueArgs...).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:AddTrustCacheFlavors() failed to create trust cache")
	}
	return fIds, nil
}

// delete from trust cache
func (hs *HostStore) RemoveTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:RemoveTrustCacheFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:RemoveTrustCacheFlavors() Leaving")

	if hId == uuid.Nil || len(fIds) <= 0 {
		defaultLog.Warn("postgres/host_store:RemoveTrustCacheFlavors()- invalid input : must have flavorId and hostId to delete from the trust cache")
		return nil
	}

	tx := hs.Store.Db
	if hId != uuid.Nil {
		tx = tx.Where("host_id = ?", hId)
	}

	if len(fIds) >= 1 {
		tx = tx.Where("flavor_id IN (?)", fIds)
	}

	if err := tx.Delete(&trustCache{}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:RemoveTrustCacheFlavors() failed to delete from trust cache")
	}
	return nil
}

// RetrieveTrustCacheFlavors function return a list of flavor ID's belonging to a host and flavorgroup
func (hs *HostStore) RetrieveTrustCacheFlavors(hId, fgId uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:RetrieveTrustCacheFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:RetrieveTrustCacheFlavors() Leaving")

	if hId == uuid.Nil || fgId == uuid.Nil {
		return nil, errors.New("postgres/host_store:RetrieveTrustCacheFlavors() Host ID and Flavorgroup ID must be set to get the list of flavors for a host belonging to a flavorgroup ID")
	}

	rows, err := hs.Store.Db.Model(&trustCache{}).Select("trust_cache.flavor_id").Joins("INNER JOIN flavorgroup_flavor ON trust_cache.flavor_id = flavorgroup_flavor.flavor_id").Where("flavorgroup_flavor.flavorgroup_id = ? AND trust_cache.host_id = ?", fgId, hId).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:RetrieveTrustCacheFlavors() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	flavorIds := []uuid.UUID{}
	for rows.Next() {
		flavorId := uuid.UUID{}
		if err := rows.Scan(&flavorId); err != nil {
			return nil, errors.Wrap(err, "postgres/host_store:RetrieveTrustCacheFlavors() failed to scan record")
		}
		flavorIds = append(flavorIds, flavorId)
	}
	return flavorIds, nil
}

func (hs *HostStore) AddHostUniqueFlavors(hId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:AddHostUniqueFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:AddHostUniqueFlavors() Leaving")
	if len(fIds) <= 0 || hId == uuid.Nil {
		return nil, errors.New("postgres/host_store:AddHostUniqueFlavors()- invalid input : must have flavorId and hostId associate flavors ")
	}

	uniqueFlavorsValues := []string{}
	uniqueFlavorsValueArgs := []interface{}{}
	for _, fId := range fIds {
		uniqueFlavorsValues = append(uniqueFlavorsValues, "(?, ?)")
		uniqueFlavorsValueArgs = append(uniqueFlavorsValueArgs, hId)
		uniqueFlavorsValueArgs = append(uniqueFlavorsValueArgs, fId)
	}

	insertQuery := fmt.Sprintf("INSERT INTO hostunique_flavor VALUES %s on conflict (host_id, flavor_id) do nothing", strings.Join(uniqueFlavorsValues, ","))
	err := hs.Store.Db.Model(hostuniqueFlavor{}).Exec(insertQuery, uniqueFlavorsValueArgs...).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:AddHostUniqueFlavors() failed to add host unique flavors")
	}
	return fIds, nil

}

func (hs *HostStore) RemoveHostUniqueFlavors(hId uuid.UUID, fIds []uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:RemoveHostUniquelavors() Entering")
	defer defaultLog.Trace("postgres/host_store:RemoveHostUniquelavors() Leaving")

	if hId == uuid.Nil && len(fIds) <= 0 {
		return errors.New("postgres/flavorgroup_store:RemoveHostUniquelavors()- invalid input : must have flavorId or hostId to delete from the host unique flavors")
	}

	tx := hs.Store.Db
	if hId != uuid.Nil {
		fmt.Println(hId.String())
		tx = tx.Where("host_id = ?", hId)
	}

	if len(fIds) >= 1 {
		fmt.Println(fIds)
		tx = tx.Where("flavor_id IN (?)", fIds)
	}

	if err := tx.Delete(&hostuniqueFlavor{}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:RemoveHostUniqueFlavors() failed to delete from host unique flavors")
	}
	return nil
}

func (hs *HostStore) RetrieveHostUniqueFlavors(hId uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:RetrieveHostUniqueFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:RetrieveHostUniqueFlavors() Leaving")

	if hId == uuid.Nil {
		return nil, errors.New("postgres/host_store:RetrieveHostUniqueFlavors() Host ID must be set to get the list of host unique flavor ids")
	}
	var flavorIds []uuid.UUID
	err := hs.Store.Db.Model(&hostuniqueFlavor{}).Where("host_id = ?", hId).Pluck("flavor_id", &flavorIds).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:RetrieveHostUniqueFlavors() failed to retrieve records from db")
	}
	return flavorIds, nil
}

func (hs *HostStore) RetrieveDistinctUniqueFlavorParts(hId uuid.UUID) ([]string, error) {
	defaultLog.Trace("postgres/host_store:RetrieveDistinctUniqueFlavorParts() Entering")
	defer defaultLog.Trace("postgres/host_store:RetrieveDistinctUniqueFlavorParts() Leaving")

	if hId == uuid.Nil {
		return nil, errors.New("postgres/host_store:RetrieveDistinctUniqueFlavorParts() Host ID must be set to get the list of host unique flavor ids")
	}
	var uniqueFlavorParts []string
	err := hs.Store.Db.Model(&flavor{}).Where("id in (select flavor_id from hostunique_flavor where host_id = ?)", hId).Pluck(("DISTINCT(flavor_part)"), &uniqueFlavorParts).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:RetrieveDistinctUniqueFlavorParts() failed to retrieve records from db")
	}
	return uniqueFlavorParts, nil
}
