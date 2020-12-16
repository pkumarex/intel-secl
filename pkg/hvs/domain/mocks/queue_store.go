/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"errors"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"time"
)

type qStore struct {
	m map[uuid.UUID]models.Queue
}

func NewQueueStore() domain.QueueStore {

	return &qStore{make(map[uuid.UUID]models.Queue)}
}

func (qs *qStore) Search(criteria *models.QueueFilterCriteria) ([]*models.Queue, error) {
	if criteria == nil || criteria.Id == uuid.Nil {
		rslt := make([]*models.Queue, 0, len(qs.m))
		for _, v := range qs.m {
			rslt = append(rslt, &v)
		}
		return rslt, nil
	}
	if _, ok := qs.m[criteria.Id]; ok {
		cp := qs.m[criteria.Id]
		return []*models.Queue{&cp}, nil
	}
	return nil, errors.New("No Records fouund")
}

func (qs *qStore) Retrieve(uuid uuid.UUID) (*models.Queue, error) {
	if _, ok := qs.m[uuid]; ok {
		cp := qs.m[uuid]
		return &cp, nil
	}
	return nil, errors.New("Record not fouund")
}

func (qs *qStore) Update(queue *models.Queue) error {
	if rec, ok := qs.m[queue.Id]; ok {

		for k, v := range queue.Params {
			rec.Params[k] = v
		}
		if queue.State > 0 {
			rec.State = queue.State
		}
		if queue.Action != "" {
			rec.Action = queue.Action
		}
		rec.Updated = time.Now()
		qs.m[queue.Id] = rec

		return nil
	}
	return errors.New("Record not found")
}

func (qs *qStore) Create(queue *models.Queue) (*models.Queue, error) {
	rec := *queue
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.New("failed to create new UUID - " + err.Error())
	}
	rec.Id = newUuid
	rec.Created = time.Now()
	rec.Updated = rec.Created
	qs.m[rec.Id] = rec
	cp := rec
	return &cp, nil
}

func (qs *qStore) Delete(uuid uuid.UUID) error {
	if _, ok := qs.m[uuid]; ok {
		delete(qs.m, uuid)
		return nil
	}
	return errors.New("Record not found")
}
