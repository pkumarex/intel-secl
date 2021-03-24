/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ManifestsController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks.MockFlavorStore
	var manifestsController *controllers.ManifestsController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorStore = mocks.NewFakeFlavorStoreWithAllFlavors("../../lib/verifier/test_data/intel20/signed_flavors.json")
		manifestsController = &controllers.ManifestsController{
			FlavorStore: flavorStore,
		}
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide a valid flavor Id", func() {
			It("Should create a manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods("GET")
				req, err := http.NewRequest("GET", "/manifests?id=bffa1025-3605-4336-9be1-a7044cb949d6", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide a flavor Id for a non SOFTWARE flavor", func() {
			It("Should fail to create manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods("GET")
				req, err := http.NewRequest("GET", "/manifests?id=49705d53-a75e-414e-998e-049cbb2a0ee6", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide a flavor Id for a non existent flavor", func() {
			It("Should fail to create manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods("GET")
				req, err := http.NewRequest("GET", "/manifests?id=339a7ac6-b8be-4356-ab34-be6e3bdfa1ee", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide an invalid flavor Id", func() {
			It("Should fail to create manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods("GET")
				req, err := http.NewRequest("GET", "/manifests?id=71e4c52e-595a-000000000000000429d-9917-1965b437c353", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
