/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

// FlavorTemplateStore to hold DB operations.
type FlavorTemplateStore struct {
	Store *DataStore
}

// NewFlavorTemplateStore to init FlavorTemplateStore.
func NewFlavorTemplateStore(store *DataStore) *FlavorTemplateStore {
	return &FlavorTemplateStore{Store: store}
}

// Create flavor template
func (ft *FlavorTemplateStore) Create(flvrTemplate *hvs.FlavorTemplate) (*hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Create() Leaving")

	if flvrTemplate.ID == uuid.Nil {
		flavorTemplateID, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Create() Failed to generate flavor template ID")
		}

		flvrTemplate.ID = flavorTemplateID
	}

	createdTemplate := flavorTemplate{
		ID:      flvrTemplate.ID,
		Content: PGFlavorTemplateContent(*flvrTemplate),
		Deleted: false,
	}

	if err := ft.Store.Db.Create(&createdTemplate).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Create() Failed to create flavor")
	}
	return flvrTemplate, nil
}

// Retrieve flavor template
func (ft *FlavorTemplateStore) Retrieve(templateID uuid.UUID, includeDeleted bool) (*hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Retrieve() Leaving")

	sf := flavorTemplate{}
	row := ft.Store.Db.Model(flavorTemplate{}).Select("id,content,deleted").Where(&flavorTemplate{ID: templateID}).Row()
	if err := row.Scan(&sf.ID, (*PGFlavorTemplateContent)(&sf.Content), &sf.Deleted); err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.Error("postgres/flavortemplate_store:Retrieve() Failed to retrieve record from db, %s", commErr.RowsNotFound)
			return nil, &commErr.StatusNotFoundError{Message: "Failed to retrieve record from db"}
		} else {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Retrieve() - Could not scan record")
		}
	}

	if includeDeleted || (!includeDeleted && !sf.Deleted) {
		flavorTemplate := hvs.FlavorTemplate{
			ID:          sf.ID,
			Label:       sf.Content.Label,
			Condition:   sf.Content.Condition,
			FlavorParts: sf.Content.FlavorParts,
		}
		return &flavorTemplate, nil
	}

	return nil, &commErr.StatusNotFoundError{Message: "FlavorTemplate with given ID is not found"}
}

// Search flavor template
func (ft *FlavorTemplateStore) Search(criteria *models.FlavorTemplateFilterCriteria) ([]hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Search() Leaving")

	tx := ft.buildFlavorTemplateSearchQuery(ft.Store.Db, criteria)
	if tx == nil {
		return nil, errors.New("postgres/flavortemplate_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("postgres/flavortemplate_store:Search() Error closing rows")
		}
	}()

	flavortemplates := []hvs.FlavorTemplate{}
	for rows.Next() {
		template := flavorTemplate{}

		if err := rows.Scan(&template.ID, (*PGFlavorTemplateContent)(&template.Content), &template.Deleted); err != nil {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Search() - Could not scan record")
		}

		flavorTemplate := hvs.FlavorTemplate{
			ID:          template.ID,
			Label:       template.Content.Label,
			Condition:   template.Content.Condition,
			FlavorParts: template.Content.FlavorParts,
		}
		flavortemplates = append(flavortemplates, flavorTemplate)
	}

	return flavortemplates, nil
}

// Delete flavor template
func (ft *FlavorTemplateStore) Delete(templateID uuid.UUID) error {
	defaultLog.Trace("postgres/flavortemplate_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Delete() Leaving")

	_, err := ft.Retrieve(templateID, false)
	if err != nil {
		switch err.(type) {
		case *commErr.StatusNotFoundError:
			defaultLog.Error("postgres/flavortemplate_store:Delete() Flavor template with given ID does not exist or has been deleted")
			return err
		default:
			return errors.Wrap(err, "postgres/flavortemplate_store:Delete() Failed to retrieve FlavorTemplate with the given ID")
		}
	}

	err = ft.Store.Db.Model(flavorTemplate{}).Where(&flavorTemplate{ID: templateID}).Update(&flavorTemplate{Deleted: true}).Error
	if err != nil {
		return errors.Wrap(err, "postgres/flavortemplate_store:Delete() - Could not Delete record "+templateID.String())
	}

	return nil
}

// Recover flavor template
func (ft *FlavorTemplateStore) Recover(recoverTemplates []string) error {
	defaultLog.Trace("postgres/flavortemplate_store:Recover() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Recover() Leaving")

	ftc := models.FlavorTemplateFilterCriteria{IncludeDeleted: true}
	templates, err := ft.Search(&ftc)
	if err != nil {
		return errors.Wrap(err, "postgres/flavortemplate_store:Recover() - Could not recover all records")
	}

	for _, template := range templates {
		for _, recover := range recoverTemplates {
			if strings.EqualFold(recover, template.Label) {
				defaultLog.Debug("postgres/flavortemplate_store:Recover() Recover default template ID ", template.ID)
				err := ft.Store.Db.Model(flavorTemplate{}).Update("deleted", false).Where(&flavorTemplate{ID: template.ID}).Error
				if err != nil {
					return errors.Wrap(err, "postgres/flavortemplate_store:Recover() - Could not recover record "+template.ID.String())
				}
			}
		}
	}

	return nil
}

func (ft *FlavorTemplateStore) buildFlavorTemplateSearchQuery(tx *gorm.DB, criteria *models.FlavorTemplateFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/flavortemplate_store:buildFlavorTemplateSearchQuery() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:buildFlavorTemplateSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&flavorTemplate{})
	if criteria == nil {
		return tx
	}

	if !criteria.IncludeDeleted {
		tx = tx.Where("deleted = ?", false)
	}

	if criteria.Id != uuid.Nil {
		tx = tx.Where("id = ?", criteria.Id)
	}
	if criteria.Label != "" {
		tx = tx.Where(convertToPgJsonqueryString("content", "label")+" = ?", criteria.Label)
	}
	if criteria.ConditionContains != "" {
		tx = tx.Where(convertToPgJsonqueryString("content", "condition")+" like ?", "%"+criteria.ConditionContains+"%")
	}
	if criteria.FlavorPartContains != "" {
		tx = tx.Where(convertToPgJsonqueryString("content", "flavor_parts")+" like ?", "%"+criteria.FlavorPartContains+"%")
	}

	return tx
}
