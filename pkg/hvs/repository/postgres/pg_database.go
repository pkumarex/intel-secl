/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/repository"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/types"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type Database struct {
	DB *gorm.DB
}

func (pd *Database) ExecuteSql(sql *string) error {

	defaultLog.Trace("ExecuteSql", sql)
	defer defaultLog.Trace("ExecuteSql done")

	err := pd.DB.Exec(*sql).Error
	if err != nil {
		return errors.Wrap(err, "pgdb: failed to execute sql")
	}
	return nil
}

func (pd *Database) ExecuteSqlFile(file string) error {

	defaultLog.Trace("ExecuteSqlFile", file)
	defer defaultLog.Trace("ExecuteSqlFile done")

	c, err := ioutil.ReadFile(file)
	if err != nil {
		return errors.Wrapf(err, "could not read sql file - %s", file)
	}
	sql := string(c)
	if err := pd.ExecuteSql(&sql); err != nil {
		return errors.Wrapf(err, "could not execute contents of sql file %s", file)
	}
	return nil
}

func (pd *Database) Migrate() error {

	defaultLog.Trace("Migrate")
	defer defaultLog.Trace("Migrate done")

	pd.DB.AutoMigrate(types.FlavorGroup{})
	return nil
}

func (pd *Database) FlavorGroupRepository() repository.FlavorGroupRepository {
	return &FlavorGroupRepository{db: pd.DB}
}

func (pd *Database) Close() {
	if pd.DB != nil {
		pd.DB.Close()
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*Database, error) {

	defaultLog.Trace("Open DB")
	defer defaultLog.Trace("Open DB done")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "require" {
		sslMode = "verify-full"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	for i := 0; i < numAttempts; i = i + 1 {
		const retryTime = 1
		db, dbErr = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
			host, port, user, dbname, password, sslMode, sslCertParams))
		if dbErr != nil {
			defaultLog.WithError(dbErr).Infof("Failed to connect to DB, retrying attempt %d/%d", i, numAttempts)
		} else {
			break
		}
		time.Sleep(retryTime * time.Second)
	}
	if dbErr != nil {
		defaultLog.WithError(dbErr).Infof("Failed to connect to db after %d attempts\n", numAttempts)
		secLog.Warningf("%s: Failed to connect to db after %d attempts", commLogMsg.BadConnection, numAttempts)
		return nil, errors.Wrapf(dbErr, "Failed to connect to db after %d attempts", numAttempts)
	}
	return &Database{DB: db}, nil
}

func VerifyConnection(host string, port int, dbname, user, password, sslMode, sslCert string) error {

	defaultLog.Trace("VerifyConnection")
	defer defaultLog.Trace("VerifyConnection done")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "verify-full"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	db, dbErr := gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
		host, port, user, dbname, password, sslMode, sslCertParams))

	if dbErr != nil {
		return errors.Wrap(dbErr, "could not connect to database")
	}
	db.Close()
	return nil
}
