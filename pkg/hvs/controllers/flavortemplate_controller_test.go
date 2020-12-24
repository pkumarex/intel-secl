/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlavorTemplateController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorTemplateStore *mocks.MockFlavorTemplateStore
	var flavorTemplateController *controllers.FlavorTemplateCreationController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorTemplateStore = mocks.NewFakeFlavorTemplateStore()

		flavorTemplateController = &controllers.FlavorTemplateCreationController{
			Store: flavorTemplateStore,
		}
	})

	// Specs for HTTP Post to "/flavor-template"
	Describe("Post a new FlavorTemplate", func() {
		Context("Provide a valid FlavorTemplate data", func() {
			It("Should create a new Flavortemplate and get HTTP Status: 200", func() {
				router.Handle("/flavor-template", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods("POST")
				flavorTemplateJson := `{
					"label": "default-uefi",
					"condition": [
						"//host_info/vendor='Linux'",
						"//host_info/tpm_version='2.0'",
						"//host_info/uefi_enabled='true'",
						"//host_info/suefi_enabled='true'"
					],
					"flavor_parts": {
						"PLATFORM": {
							"meta": {
								"tpm_version": "2.0",
								"uefi_enabled": true,
								"vendor": "Linux"
							},
							"pcr_rules": [
								{
									"pcr": {
										"index": 0,
										"bank": "SHA256"
									},
									"pcr_matches": true,
									"eventlog_equals": {}
								}
							]
						},
						"OS": {
							"meta": {
								"tpm_version": "2.0",
								"uefi_enabled": true,
								"vendor": "Linux"
							},
							"pcr_rules": [
								{
									"pcr": {
										"index": 7,
										"bank": "SHA256"
									},
									"pcr_matches": true,
									"eventlog_includes": [
										"shim",
										"db",
										"kek",
										"vmlinuz"
									]
								}
							]
						}
					}
				}`

				req, err := http.NewRequest(
					"POST",
					"/flavor-template",
					strings.NewReader(flavorTemplateJson),
				)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})
	})
	// 	Context("Provide a Flavorgroup data that contains duplicate flavorgroup name", func() {
	// 		It("Should get HTTP Status: 400", func() {
	// 			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Create))).Methods("POST")
	// 			flavorgroupJson := `{
	// 								"name": "hvs_flavorgroup_test1",
	// 								"flavor_match_policy_collection": {
	// 									"flavor_match_policies": [
	// 										{
	// 											"flavor_part": "HOST_UNIQUE",
	// 											"match_policy": {
	// 												"match_type": "ALL_OF",
	// 												"required": "REQUIRED_IF_DEFINED"
	// 											}
	// 										}
	// 									]
	// 								}
	// 							}`

	// 			req, err := http.NewRequest(
	// 				"POST",
	// 				"/flavorgroups",
	// 				strings.NewReader(flavorgroupJson),
	// 			)
	// 			req.Header.Set("Accept", consts.HTTPMediaTypeJson)
	// 			req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
	// 			Expect(err).NotTo(HaveOccurred())
	// 			w = httptest.NewRecorder()
	// 			router.ServeHTTP(w, req)
	// 			Expect(w.Code).To(Equal(400))
	// 		})
	// 	})
	// })

	Describe("Search And Delete Flavor Templates", func() {
		Context("When no filter arguments are passed", func() {
			It("All Flavor template records are returned", func() {
				router.Handle("/flavor-template/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavor-template/", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft *[]hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
			})
		})
		Context("Delete a template", func() {
			It("The templates should be deleted", func() {
				router.Handle("/flavor-template/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavor-template/426912bd-39b0-4daa-ad21-0c6933230b51", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
		Context("Delete a template", func() {
			It("The templates should be deleted", func() {
				router.Handle("/flavor-template/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavor-template/426912bd-39b0-4daa-ad21-0c6933230b50", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("When include_deleted parameter is added", func() {
			It("All Flavor template records are returned", func() {
				router.Handle("/flavor-template/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavor-template/?include_deleted=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ft)).To(Equal(1))
			})
		})
	// 		It("Should get a single flavor entry", func() {
	// 			router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods("GET")
	// 			req, err := http.NewRequest("GET", "/flavors?id=c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
	// 			Expect(err).NotTo(HaveOccurred())
	// 			req.Header.Set("Accept", consts.HTTPMediaTypeJson)
	// 			w = httptest.NewRecorder()
	// 			router.ServeHTTP(w, req)
	// 			Expect(w.Code).To(Equal(http.StatusOK))

	// 			var sfs *hvs.SignedFlavorCollection
	// 			err = json.Unmarshal(w.Body.Bytes(), &sfs)
	// 			Expect(err).NotTo(HaveOccurred())
	// 			Expect(len(sfs.SignedFlavors)).To(Equal(1))
	// 		})
	// 	})
	// 	Context("When filtered by Flavor meta description key-value pair", func() {
	// 		It("Should get a single flavor entry", func() {
	// 			router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods("GET")
	// 			req, err := http.NewRequest("GET", "/flavors?key=bios_name&&value=Intel Corporation", nil)
	// 			Expect(err).NotTo(HaveOccurred())
	// 			req.Header.Set("Accept", consts.HTTPMediaTypeJson)
	// 			w = httptest.NewRecorder()
	// 			router.ServeHTTP(w, req)
	// 			Expect(w.Code).To(Equal(http.StatusOK))

	// 			var sfs *hvs.SignedFlavorCollection
	// 			err = json.Unmarshal(w.Body.Bytes(), &sfs)
	// 			Expect(err).NotTo(HaveOccurred())
	// 			//TODO Requires changes in mock flavor search method for this criteria
	// 			Expect(len(sfs.SignedFlavors)).To(Equal(0))
	// 		})
	// 	})
	 })
})
