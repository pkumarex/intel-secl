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
	var flavorTemplateController *controllers.FlavorTemplateController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorTemplateStore = mocks.NewFakeFlavorTemplateStore()

		flavorTemplateController = controllers.NewFlavorTemplateController(flavorTemplateStore,
			"../domain/schema/common.schema.json", "../domain/schema/flavor-template.json")
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
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a FlavorTemplate data that contains invalid fileds, to validate against schema", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavor-template", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods("POST")
				flavorgroupJson := `{
					"label": "",
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
								"tboot_installed": true
							},
							"pcr_rules": [
								{
									"pcr": {
										"index": 0,
										"bank": "SHA256"
									},
									"pcr_matches": true
								}
							]
						}
					}
				}`

				req, err := http.NewRequest(
					"POST",
					"/flavor-template",
					strings.NewReader(flavorgroupJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a empty data that should give bad request error", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavor-template", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods("POST")
				req, err := http.NewRequest(
					"POST",
					"/flavor-template",
					strings.NewReader(""),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a valid FlavorTemplate data without ACCEPT header", func() {
			It("Should give HTTP Status: 415", func() {
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
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a valid FlavorTemplate data without Content-Type header", func() {
			It("Should give HTTP Status: 415", func() {
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
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

	})

	// Specs for HTTP Post to "/flavor-template/{flavor-template-id}"
	Describe("Retrieve a FlavorTemplate", func() {
		Context("Retrieve data with valid FlavorTemplate ID", func() {
			It("Should retrieve Flavortemplate data and get HTTP Status: 200", func() {
				router.Handle("/flavor-template/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavor-template/426912bd-39b0-4daa-ad21-0c6933230b50", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve data with unavailable FlavorTemplate ID", func() {
			It("Should not retrieve Flavortemplate data and get HTTP Status: 404", func() {
				router.Handle("/flavor-template/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavor-template/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Retrieve data with invalid FlavorTemplate ID", func() {
			It("Should not retrieve Flavortemplate data and get HTTP Status: 404", func() {
				router.Handle("/flavor-template/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavor-template/2f5cf0ec-0000-0000-0000-000000000000", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

	})

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
				Expect(w.Code).To(Equal(http.StatusNotFound))
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
	})
})
