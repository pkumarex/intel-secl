/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/pkg/errors"

	"github.com/google/uuid"
)

/**
 *
 * @author purvades
 */

// ImageFlavor is a flavor for an image with the encryption requirement information
// and key details of an encrypted image.
type ImageFlavor struct {
	Image model.Image `json:"flavor"`
}

// GetImageFlavor is used to create a new image flavor with the specified label, encryption policy,
// key url, and digest of the encrypted image
func GetImageFlavor(label string, encryptionRequired bool, keyURL string, digest string) (*ImageFlavor, error) {

	var encryption *model.Encryption

	description := map[string]interface{}{model.Label: label, model.FlavorPart: "IMAGE"}

	meta := model.Meta{
		ID:          uuid.New(),
		Description: description,
	}

	if encryptionRequired {
		encryption = &model.Encryption{
			KeyURL: keyURL,
			Digest: digest,
		}
	}

	imageflavor := model.Image{
		Meta:               meta,
		EncryptionRequired: encryptionRequired,
		Encryption:         encryption,
	}

	flavor := ImageFlavor{
		Image: imageflavor,
	}
	return &flavor, nil
}

// GetContainerImageFlavor is used to create a new container image flavor with the specified label, encryption policy,
// Key url of the encrypted image also integrity policy and notary url for docker image signature verification
func GetContainerImageFlavor(label string, encryptionRequired bool, keyURL string, integrityEnforced bool, notaryURL string) (*ImageFlavor, error) {
	var encryption *model.Encryption
	var integrity *model.Integrity

	if label == "" {
		return nil, errors.Errorf("label cannot be empty")
	}

	description := map[string]interface{}{model.Label: label, model.FlavorPart: "CONTAINER_IMAGE"}

	meta := model.Meta{
		ID:          uuid.New(),
		Description: description,
	}

	encryption = &model.Encryption{
		KeyURL: keyURL,
	}

	integrity = &model.Integrity{
		NotaryURL: notaryURL,
	}

	containerImageFlavor := model.Image{
		Meta:               meta,
		EncryptionRequired: encryptionRequired,
		Encryption:         encryption,
		IntegrityEnforced:  integrityEnforced,
		Integrity:          integrity,
	}

	flavor := ImageFlavor{
		Image: containerImageFlavor,
	}
	return &flavor, nil
}
