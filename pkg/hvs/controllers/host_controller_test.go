/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	smocks "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/mocks"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HostController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var flavorStore *mocks.MockFlavorStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController *controllers.HostController
	var hostTrustManager *smocks.MockHostTrustManager
	var hostControllerConfig domain.HostControllerConfig
	var hostConnectorProvider mocks2.MockHostConnectorFactory
	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorStore = mocks.NewMockFlavorStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()

		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, err := base64.StdEncoding.DecodeString(dekBase64)
		Expect(err).NotTo(HaveOccurred())
		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     dek,
			Username:              "fakeuser",
			Password:              "fakepassword",
		}

		hostController = &controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FStore:    flavorStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}
	})

	// Specs for HTTP Post to "/hosts"
	Describe("Create a new Host", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://another.ta.ip.com:1443",
								"description": "Another Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Create request that contains duplicate hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost2",
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without connection string", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains malformed connection string", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://t a.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "local host",
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a Create request that contains invalid connection strings", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods("POST")
				hostJson1 := `{
								"host_name": "localhost",
								"connection_string": "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
								"description": "Intel Host"
							}`

				hostJson2 := `{
								"host_name": "localhost",
								"connection_string": "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//–>\">'>"",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson1),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				req, err = http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson2),
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

	// Specs for HTTP Get to "/hosts/{hId}"
	Describe("Retrieve an existing Host", func() {
		Context("Retrieve Host by ID", func() {
			It("Should retrieve a Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve Host by non-existent ID", func() {
			It("Should fail to retrieve Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Put to "/hosts/{hId}"
	Describe("Update an existing Host", func() {
		Context("Provide a valid Host data", func() {
			It("Should update an existing Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "127.0.0.1",
								"connection_string": "intel:https://127.0.0.1:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a Host data that contains malformed connection string", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "localhost1",
								"connection_string": "intel:https://t a.ip.com:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Host data that contains invalid hostname", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "local host",
								"connection_string": "intel:https://ta.ip.com:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existent Host data", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "localhost1",
								"connection_string": "intel:https://ta.ip.com:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/73755fda-c910-46be-821f-e8ddeab189e9",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/hosts/{hId}"
	Describe("Delete an existing Host", func() {
		Context("Delete Host by ID", func() {
			It("Should delete a Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete Host by non-existent ID", func() {
			It("Should fail to delete Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/hosts/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/hosts"
	Describe("Search for all the Hosts", func() {
		Context("Get all the Hosts", func() {
			It("Should get list of all the Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 2 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(2))
			})
		})
		Context("Get all the Hosts with key value params", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?key=os_name&value=RedHatEnterprise", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 0 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(0))
			})
		})
		Context("Get all the Hosts with valid nameEqualTo param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?nameEqualTo=localhost1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts with valid nameContains param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?nameContains=localhost", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 2 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(2))
			})
		})
		Context("Get all the Hosts with invalid nameEqualTo param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?nameEqualTo=local host1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with invalid nameContains param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?nameContains=local host", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with valid id param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?id=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts with valid hostHardwareId param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?hostHardwareId=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts with invalid id param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?id=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with invalid hostHardwareId param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?hostHardwareId=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Post to "/hosts/{hId}/flavorgroups"
	Describe("Create a new Host Flavorgroup link", func() {
		Context("Provide a valid Flavorgroup Id", func() {
			It("Should create a new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods("POST")
				hostJson := `{
								"flavorgroup_id": "ee37c360-7eae-4250-a677-6ee12adce8e2"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a linked Flavorgroup Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods("POST")
				hostJson := `{
								"flavorgroup_id": "e57e5ea0-d465-461e-882d-1600090caa0d"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existing Host Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods("POST")
				hostJson := `{
								"flavorgroup_id": "e57e5ea0-d465-461e-882d-1600090caa0d"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts/73755fda-c910-46be-821f-e8ddeab189e9/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Provide a non-existing Flavorgroup Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods("POST")
				hostJson := `{
								"flavorgroup_id": "73755fda-c910-46be-821f-e8ddeab189e9"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide an invalid Flavorgroup Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods("POST")
				hostJson := `{
								"flavorgroup_id": "e57e5ea0-d465-461e-882d-"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/hosts/{hId}/flavorgroups/{fgId}"
	Describe("Retrieve an existing Host Flavorgroup link", func() {
		Context("Retrieve by Host Id and Flavorgroup Id", func() {
			It("Should retrieve a Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.RetrieveFlavorgroup))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve by non-existent Host Id", func() {
			It("Should fail to retrieve Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.RetrieveFlavorgroup))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/73755fda-c910-46be-821f-e8ddeab189e9/flavorgroups/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Retrieve by non-existent Flavorgroup Id", func() {
			It("Should fail to retrieve Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.RetrieveFlavorgroup))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/hosts/{hId}/flavorgroups/{fgId}"
	Describe("Delete an existing Host Flavorgroup link", func() {
		Context("Delete by host Id and Flavorgroup Id", func() {
			It("Should delete a Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.RemoveFlavorgroup))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete by non-existent Host Id", func() {
			It("Should fail to delete Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.RemoveFlavorgroup))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/hosts/73755fda-c910-46be-821f-e8ddeab189e9/flavorgroups/", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Delete by non-existent Flavorgroup Id", func() {
			It("Should fail to delete Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.RemoveFlavorgroup))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/hosts/{hId}/flavorgroups"
	Describe("Search for all the Host Flavorgroup links", func() {
		Context("Get all the Host Flavorgroup links for a Host", func() {
			It("Should get list of all the Host Flavorgroup links associated with Host", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.SearchFlavorgroups))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostFlavorgroupCollection hvs.HostFlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostFlavorgroupCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host flavorgroup link
				Expect(len(hostFlavorgroupCollection.HostFlavorgroups)).To(Equal(1))
			})
		})
	})
})
