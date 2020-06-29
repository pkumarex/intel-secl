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
	"strings"
	"reflect"
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
		HardwareUuid:     h.HardwareUuid,
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

func (hs *HostStore) Update(h *hvs.Host) (*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Update() Entering")
	defer defaultLog.Trace("postgres/host_store:Update() Leaving")

	dbHost := host{
		Id:               h.Id,
		Name:             h.HostName,
		Description:      h.Description,
		ConnectionString: h.ConnectionString,
		HardwareUuid:     h.HardwareUuid,
	}

	if err := hs.Store.Db.Save(&dbHost).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:Update() failed to update Host")
	}
	return h, nil
}

func (hs *HostStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:Delete() Entering")
	defer defaultLog.Trace("postgres/host_store:Delete() Leaving")

	if err := hs.Store.Db.Delete(&host{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:Delete() failed to delete Host")
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
	defer rows.Close()

	var hosts []*hvs.Host
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

// create trust cache
func (hs *HostStore) AddTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:AddTrustCacheFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:AddTrustCacheFlavors() Leaving")
	if len(fIds)  <=0 || hId == uuid.Nil {
		return nil, errors.New("postgres/host_store:AddTrustCacheFlavors()- invalid input : must have flavorId and hostId to create the trust cache")
	}

	trustCacheValues := []string{}
	trustCacheValueArgs := []interface{}{}
	for _, fId := range fIds {
		trustCacheValues = append(trustCacheValues, "(?, ?, ?)")
		trustCacheValueArgs = append(trustCacheValueArgs, uuid.New())
		trustCacheValueArgs = append(trustCacheValueArgs, fId)
		trustCacheValueArgs = append(trustCacheValueArgs, hId)
	}

	insertQuery := fmt.Sprintf("INSERT INTO trust_cache VALUES %s", strings.Join(trustCacheValues, ","))
	err := hs.Store.Db.Model(trustCache{}).AddForeignKey("flavor_id", "flavors(id)", "RESTRICT", "RESTRICT").AddForeignKey("host_id", "hosts(id)", "RESTRICT", "RESTRICT").Exec(insertQuery, trustCacheValueArgs...).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:AddTrustCacheFlavors() failed to create trust cache")
	}
	return fIds, nil
}

// delete from trust cache
func (hs *HostStore) RemoveTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) (error) {
	defaultLog.Trace("postgres/host_store:RemoveTrustCacheFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:RemoveTrustCacheFlavors() Leaving")

	if (hId == uuid.Nil && len(fIds) <=0) {
		return errors.New("postgres/flavorgroup_store:RemoveTrustCacheFlavors()- invalid input : must have flavorId or hostId to delete from the trust cache")
	}

	tx := hs.Store.Db
	if hId != uuid.Nil {
		fmt.Println(hId.String())
		tx = tx.Where("host_id = ?", hId)
	}

	if len(fIds) >=1 {
		fmt.Println(fIds)
		tx = tx.Where("flavor_id IN (?)", fIds)
	}

	if err := tx.Delete(&trustCache{}).Error ; err != nil {
		return errors.Wrap(err, "postgres/host_store:RemoveTrustCacheFlavors() failed to delete from trust cache")
	}
	return nil
}

// RetrieveTrustCacheFlavors function return a list of flavor ID's belonging to a host and flavorgroup
func (hs *HostStore) RetrieveTrustCacheFlavors(hId, fgId uuid.UUID ) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/host_store:RetrieveTrustCacheFlavors() Entering")
	defer defaultLog.Trace("postgres/host_store:RetrieveTrustCacheFlavors() Leaving")

	if hId == uuid.Nil || fgId == uuid.Nil {
		return nil, errors.New("postgres/host_store:RetrieveTrustCacheFlavors() Host ID and Flavorgroup ID must be set to get the list of flavors for a host belonging to a flavorgroup ID")
	}

	rows, err := hs.Store.Db.Model(&trustCache{}).Select("trust_cache.flavor_id").Joins("INNER JOIN flavorgroup_flavors ON trust_cache.flavor_id = flavorgroup_flavors.flavor_id").Where("flavorgroup_flavors.flavorgroup_id = ? AND trust_cache.host_id = ?", fgId, hId).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:RetrieveTrustCacheFlavors() failed to retrieve records from db")
	}
	defer rows.Close()

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