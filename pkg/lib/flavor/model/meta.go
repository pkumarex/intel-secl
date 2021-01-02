<<<<<<< HEAD
/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"github.com/google/uuid"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
)

/**
 *
 * @author purvades
 */

// Meta holds metadata information related to the Flavor
type Meta struct {
	Schema *Schema `json:"schema,omitempty"`
	// swagger:strfmt uuid
	ID          uuid.UUID              `json:"id"`
	Realm       string                 `json:"realm,omitempty"`
	Description map[string]interface{} `json:"description,omitempty"`
	Vendor      hcConstants.Vendor     `json:"vendor,omitempty"`
}

// Schema defines the Uri of the schema
type Schema struct {
	Uri string `json:"uri,omitempty"`
}
=======
/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"github.com/google/uuid"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
)

/**
 *
 * @author purvades
 */

// Meta holds metadata information related to the Flavor
type Meta struct {
	Schema *Schema `json:"schema,omitempty"`
	// swagger:strfmt uuid
	ID          uuid.UUID          `json:"id"`
	Realm       string             `json:"realm,omitempty"`
	Description Description        `json:"description,omitempty"`
	Vendor      hcConstants.Vendor `json:"vendor,omitempty"`
}

// Schema defines the Uri of the schema
type Schema struct {
	Uri string `json:"uri,omitempty"`
}
>>>>>>> e89ea91ffdf485e64a2cdbd1deeb06628e9a8ea3
