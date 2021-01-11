/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	smocks "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/mocks"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlavorgroupController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorgroupStore *mocks2.MockFlavorgroupStore
	var flavorStore *mocks2.MockFlavorStore
	var hostStore *mocks2.MockHostStore
	var flavorgroupController *controllers.FlavorgroupController
	var htm *smocks.MockHostTrustManager
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorgroupStore = mocks2.NewFakeFlavorgroupStore()
		flavorStore = mocks2.NewMockFlavorStore()
		hostStore = mocks2.NewMockHostStore()

		_, err := flavorgroupStore.AddFlavors(uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
			[]uuid.UUID{
				uuid.MustParse("c36b5412-8c02-4e08-8a74-8bfa40425cf3"),
			})
		Expect(err).NotTo(HaveOccurred())
		_, err = flavorgroupStore.AddFlavors(uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			[]uuid.UUID{
				uuid.MustParse("c36b5412-8c02-4e08-8a74-8bfa40425cf3"),
			})
		Expect(err).NotTo(HaveOccurred())
		flavorgroupController = &controllers.FlavorgroupController{
			FlavorGroupStore: flavorgroupStore,
			FlavorStore:      flavorStore,
			HostStore:        hostStore,
			HTManager:        htm,
		}
	})

	// Specs for HTTP Get to "/flavorgroups"
	Describe("Get list of FlavorGroups", func() {
		Context("Get all FlavorGroups from data store", func() {
			It("Should get list of FlavorGroups", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fgCollection.Flavorgroups)).To(Equal(2))
			})
		})
		Context("Search FlavorGroups from data store", func() {
			It("Should get filtered list of FlavorGroups", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?nameEqualTo=hvs_flavorgroup_test2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fgCollection.Flavorgroups)).To(Equal(1))
			})
		})
		Context("Search FlavorGroups from data store", func() {
			It("Should get filtered list of FlavorGroups", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?nameContains=hvs_flavorgroup", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fgCollection.Flavorgroups)).To(Equal(2))
			})
		})
		Context("Get all FlavorGroups from data store with flavor content", func() {
			It("Should get list of FlavorGroups with flavor content", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?includeFlavorContent=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fgCollection.Flavorgroups)).To(Equal(2))
			})
		})
	})

	// Specs for HTTP Get to "/flavorgroups/{flavorgroup_id}"
	Describe("Get FlavorGroup by ID", func() {
		Context("Retrieve FlavorGroup by ID from data store", func() {
			It("Should retrieve FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})
		Context("Try to retrieve FlavorGroup by invalid ID from data store", func() {
			It("Should fail to retrieve FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Delete to "/flavorgroups/{flavorgroup_id}"
	Describe("Delete FlavorGroup by ID", func() {
		Context("Delete FlavorGroup by ID from data store", func() {
			It("Should delete FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})

		Context("Delete FlavorGroup by invalid ID from data store", func() {
			It("Should fail to delete FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Post to "/flavorgroups"
	Describe("Post a new Flavorgroup", func() {
		Context("Provide a valid Flavorgroup data", func() {
			It("Should create a new Flavorgroup and get HTTP Status: 201", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Create))).Methods("POST")
				flavorgroupJson := `{
								"name": "hvs_flavorgroup_new",
								"flavor_match_policy_collection": {
									"flavor_match_policies": [
										{
											"flavor_part": "PLATFORM",
											"match_policy": {
												"match_type": "ANY_OF",
												"required": "REQUIRED"
											}
										},
										{
											"flavor_part": "OS",
											"match_policy": {
												"match_type": "ANY_OF",
												"required": "REQUIRED"
											}
										},
										{
											"flavor_part": "HOST_UNIQUE",
											"match_policy": {
												"match_type": "LATEST",
												"required": "REQUIRED_IF_DEFINED"
											}
										}
									]
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups",
					strings.NewReader(flavorgroupJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})

		Context("Provide a Flavorgroup data that contains duplicate flavorgroup name", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Create))).Methods("POST")
				flavorgroupJson := `{
								"name": "hvs_flavorgroup_test1",
								"flavor_match_policy_collection": {
									"flavor_match_policies": [
										{
											"flavor_part": "HOST_UNIQUE",
											"match_policy": {
												"match_type": "ALL_OF",
												"required": "REQUIRED_IF_DEFINED"
											}
										}
									]
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups",
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
	})

	Context("Provide a empty data  in request", func() {
		It("Should get HTTP Status: 400", func() {
			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Create))).Methods("POST")
			flavorgroupJson := ``
			req, err := http.NewRequest(
				"POST",
				"/flavorgroups",
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

	Context("Provide a invalid Flavorgroup data", func() {
		It("Should get HTTP Status: 400", func() {
			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Create))).Methods("POST")
			flavorgroupJson := `{
								"id": "hvs_flavorgroup_test1",
								"flavor_match_policy_collection": {
									"flavor_part": [
										{
											"flavor_part": "HOST_UNIQUE",
										}
									]
								}
							}`

			req, err := http.NewRequest(
				"POST",
				"/flavorgroups",
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

	Context("Provide a incorrect Flavorgroup data", func() {
		It("Should get HTTP Status: 400", func() {
			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.Create))).Methods("POST")
			flavorgroupJson := `{
								"name": "hvs_flavorgroup_test1",
								"flavor_match_policy_collection": {
									"flavor_part": []
								}
							}`

			req, err := http.NewRequest(
				"POST",
				"/flavorgroups",
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

	// Specs for flavorGroup validation
	Describe("FlavorGroup Validation", func() {
		Context("FlavorGroup with correct content", func() {
			It("should pass flavorGroup validation", func() {
				flavorgroupJson := `{
								"name": "hvs_flavorgroup_test1",
								"flavor_match_policy_collection": {
									"flavor_match_policies": [
										{
											"flavor_part": "HOST_UNIQUE",
											"match_policy": {
												"match_type": "ALL_OF",
												"required": "REQUIRED_IF_DEFINED"
											}
										}
									]
								}
							}`

				flavorGroup := hvs.FlavorGroup{}
				err := json.Unmarshal([]byte(flavorgroupJson), &flavorGroup)
				Expect(err).NotTo(HaveOccurred())
				err = controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).ShouldNot(HaveOccurred())
			})
		})
		Context("FlavorGroup with incorrect content", func() {
			It("should fail flavorGroup validation", func() {
				flavorgroupJson := `{
								"flavor_match_policy_collection": {
									"name": "hvs_flavorgroup_test1",
									"flavor_match_policies": [
										{
											"flavor_part": "HOST_UNIQUE",
											"match_policy": {
												"match_type": "ALL_OF",
												"required": "REQUIRED_IF_DEFINED"
											}
										}
									]
								}
							}`

				flavorGroup := hvs.FlavorGroup{}
				err := json.Unmarshal([]byte(flavorgroupJson), &flavorGroup)
				Expect(err).NotTo(HaveOccurred())
				flavorGroup.Name = ""
				err = controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).Should(HaveOccurred())

				flavorGroup.Name = "####"
				err = controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).Should(HaveOccurred())

				flavorGroup.Name = "test"
				flavorGroup.MatchPolicies = hvs.FlavorMatchPolicies{}
				err = controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).Should(HaveOccurred())
			})
		})
	})

	// Specs for FlavorGroupFilterCriteria validation
	Describe("FlavorGroupFilterCriteria Validation", func() {
		Context("FlavorGroupFilterCriteria with correct/empty content", func() {
			It("should pass FlavorGroupFilterCriteria validation", func() {
				filterCriteria := models.FlavorGroupFilterCriteria{}
				err := controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).ShouldNot(HaveOccurred())
			})
		})
		Context("FlavorGroupFilterCriteria with incorrect content", func() {
			It("should fail FlavorGroupFilterCriteria validation", func() {
				filterCriteria := models.FlavorGroupFilterCriteria{
					NameContains: "####",
				}
				err := controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).Should(HaveOccurred())

				filterCriteria = models.FlavorGroupFilterCriteria{
					NameEqualTo: "####",
				}
				err = controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).Should(HaveOccurred())
			})
		})
	})

	// FlavorGroupFlavor Create link API tests
	// Specs for HTTP POST to "flavorgroups/{flavorgroup_id}/flavors"
	Describe("Create FlavorGroupFlavor Links", func() {
		Context("Create FlavorGroup-Flavor link with valid FlavorGroup ID and valid Flavor ID", func() {
			BeforeEach(func() {
				// add unlinked flavor here
				sf1, err := flavorStore.Retrieve(uuid.MustParse("c36b5412-8c02-4e08-8a74-8bfa40425cf3"))
				Expect(err).NotTo(HaveOccurred())
				sf1.Flavor.Meta.ID = uuid.MustParse("f452b331-87f7-4274-a3d2-e31a471d159e")
				_, err = flavorStore.Create(sf1)
				Expect(err).NotTo(HaveOccurred())
			})
			It("Should create FlavorGroupFlavor link in store and return 201 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "f452b331-87f7-4274-a3d2-e31a471d159e"
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Create FlavorGroup-Flavor link with valid FlavorGroup ID and valid Flavor ID which is already linked to flavorgroup", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "c36b5412-8c02-4e08-8a74-8bfa40425cf3"
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Create FlavorGroup-Flavor link with empty POST body", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Create FlavorGroup-Flavor link with invalid FlavorGroup and valid Flavor ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "f452b331-87f7-4274-a3d2-e31a471d159e"
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/invalid-7eae-4250-a677-6ee12adce8e2/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Create FlavorGroup-Flavor link with non-existent FlavorGroup and valid Flavor ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "f452b331-87f7-4274-a3d2-e31a471d159e"
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/9c41f744-cf17-4c53-8d49-888ebb6af99f/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Create FlavorGroup-Flavor link with non-existent FlavorGroup and invalid Flavor ID", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "thisisanINVALID-8c02-4e08-8a74-8bfa40425cf3"
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/9c41f744-cf17-4c53-8d49-888ebb6af99f/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Create FlavorGroup-Flavor link with valid FlavorGroup and invalid Flavor ID", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "BLAHBLAHBLAHBLAH-8c02-4e08-8a74-8bfa40425cf3"
							}`

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Create FlavorGroup-Flavor link with valid FlavorGroup and non-existent Flavor ID", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{
								"flavor_id": "da24fa11-9e69-4f56-89fe-29deef6289af"
							}`
				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Create FlavorGroup-Flavor link with valid FlavorGroup and nil Flavor ID", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.AddFlavor))).Methods("POST")
				flavorJson := `{"flavor_id": ` + uuid.Nil.String() + `}`
				req, err := http.NewRequest(
					"POST",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// ----------------------------
	// FlavorGroupFlavor Delete link API tests
	// Specs for HTTP DELETE to "flavorgroups/{flavorgroup_id}/flavors/{flavor_id}"
	Describe("Delete FlavorGroupFlavor Links", func() {
		Context("Delete FlavorGroup-Flavor link with valid FlavorGroup ID and valid Flavor ID", func() {
			It("Should Delete FlavorGroupFlavor link in store and return 204 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors/{fID:"+validation.UUIDReg+"}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.RemoveFlavor))).Methods("DELETE")
				req, err := http.NewRequest(
					"DELETE",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Delete FlavorGroup-Flavor link with non-existent FlavorGroup and valid Flavor ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors/{fID:"+validation.UUIDReg+"}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.RemoveFlavor))).Methods("DELETE")
				req, err := http.NewRequest(
					"DELETE",
					"/flavorgroups/9c41f744-cf17-4c53-8d49-888ebb6af99f/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Delete FlavorGroup-Flavor link with valid FlavorGroup and non-existent Flavor ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.RemoveFlavor))).Methods("DELETE")

				req, err := http.NewRequest(
					"DELETE",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors/b96180a3-834c-4426-a5d0-7c92ef6d0cd7",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// FlavorGroupFlavor Search links API tests
	// Specs for HTTP GET to "flavorgroups/{flavorgroup_id}/flavors"
	Describe("Search FlavorGroupFlavor Links", func() {
		Context("Search FlavorGroup-Flavor link with valid FlavorGroup ID", func() {
			It("Should return a list of FlavorGroupFlavor links and 200 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.SearchFlavors))).Methods("GET")
				req, err := http.NewRequest(
					"GET",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
				var fgfl hvs.FlavorgroupFlavorLinkCollection
				Expect(json.Unmarshal(w.Body.Bytes(), &fgfl)).NotTo(HaveOccurred())
				Expect(len(fgfl.FGFLinks) > 0).To(BeTrue())
			})
		})

		Context("Search FlavorGroup-Flavor link with non-existent FlavorGroup ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.SearchFlavors))).Methods("GET")
				req, err := http.NewRequest(
					"GET",
					"/flavorgroups/0ae3f0a1-afe6-4efc-98de-c4e346441b94/flavors",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// FlavorGroupFlavor Retrieve links API tests
	// Specs for HTTP GET to "flavorgroups/{flavorgroup_id}/flavors/{flavor_id}"
	Describe("Retrieve FlavorGroupFlavor Links", func() {
		Context("Retrieve FlavorGroup-Flavor link with valid FlavorGroup ID and valid Flavor ID", func() {
			It("Should Retrieve FlavorGroupFlavor link in store and return 200 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors/{fID:"+validation.UUIDReg+"}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.RetrieveFlavor))).Methods("GET")
				req, err := http.NewRequest(
					"GET",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve FlavorGroup-Flavor link with non-existent FlavorGroup and valid Flavor ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors/{fID:"+validation.UUIDReg+"}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.RetrieveFlavor))).Methods("GET")
				req, err := http.NewRequest(
					"GET",
					"/flavorgroups/9c41f744-cf17-4c53-8d49-888ebb6af99f/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Retrieve FlavorGroup-Flavor link with valid FlavorGroup and non-existent Flavor ID", func() {
			It("Should return 404 response code", func() {
				router.Handle("/flavorgroups/{fgID:"+validation.UUIDReg+"}/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorgroupController.RetrieveFlavor))).Methods("GET")

				req, err := http.NewRequest(
					"GET",
					"/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2/flavors/b96180a3-834c-4426-a5d0-7c92ef6d0cd7",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
})
