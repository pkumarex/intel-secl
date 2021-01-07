/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	smocks "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/mocks"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"strings"
)

var _ = Describe("ESXiClusterController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var esxiClusterStore *mocks.MockESXiClusterStore
	var esxiClusterController *controllers.ESXiClusterController
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController *controllers.HostController
	var hostTrustManager *smocks.MockHostTrustManager
	var hostConnectorProvider mocks2.MockHostConnectorFactory

	BeforeEach(func() {
		router = mux.NewRouter()
		esxiClusterStore = mocks.NewFakeESXiClusterStore()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()
		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, _ := base64.StdEncoding.DecodeString(dekBase64)

		hostControllerConfig := domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     dek,
			Username:              "fakeuser",
			Password:              "fakepassword",
		}
		hostController = &controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}
		esxiClusterController = &controllers.ESXiClusterController{ECStore: esxiClusterStore,
			HController: *hostController}
	})

	// Specs for HTTP Get to "/esxi-cluster"
	Describe("Search ESXi cluster", func() {
		Context("Search esxi cluster records when no filter arguments are passed", func() {
			It("All ESXi cluster records are returned", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/esxi-cluster", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(2))
			})
		})

		Context("Search esxi cluster records when filtered by ESXi cluster id", func() {
			It("Should get a single ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/esxi-cluster?id=40c6ec42-ee9a-4d8a-842b-cdcd0fefa9c0", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(1))
			})
		})

		Context("Search esxi cluster records when filtered by an invalid ESXi cluster id", func() {
			It("Should get a HTTP bad request status", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods("GET")
				req, err := http.NewRequest("GET",
					"/esxi-cluster?id=13885605-a0ee-41f20000000000000000000000-b6fc-fd82edc487ad", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).To(HaveOccurred())
				Expect(ecCollection).To(BeNil())
			})
		})

		Context("Search esxi cluster records when filtered by ESXi cluster name", func() {
			It("Should get a single ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/esxi-cluster?clusterName=Cluster 1", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(1))
			})
		})

		Context("Search esxi cluster records when filtered by ESXi cluster name", func() {
			It("Should not get any ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/esxi-cluster?clusterName=Unregistered cluster", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(ecCollection.ESXiCluster).To(BeNil())
			})
		})
	})

	Describe("Retrieve ESXi cluster record", func() {
		Context("Retrieve ESXi cluster by valid ID from data store", func() {
			It("Should retrieve ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/esxi-cluster/f3c6a763-51cd-436c-a828-c2ce6964c823", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Try to retrieve ESXi cluster by non-existent ID from data store", func() {
			It("Should fail to retrieve ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/esxi-cluster/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).To(HaveOccurred())
				Expect(ecCollection).To(BeNil())
			})
		})
	})

	Describe("Create ESXi cluster entry", func() {
		Context("Provide a valid ESXi cluster data", func() {
			It("Should create ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods("POST")
				esxiClusterRequestJson := `{
					"connection_string": "https://ip3.com:443/sdk;u=username;p=password",
					"cluster_name": "New Cluster"
				}`
				req, err := http.NewRequest("POST", "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide an invalid request body to create a new ESXi cluster record", func() {
			It("Should have HTTP bad request status", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods("POST")
				esxiClusterRequestJson := `{
					"connectionString": "https://ip3.com:443/sdk;u=username;p=password",
					"clusterName": "New Cluster"
				}`
				req, err := http.NewRequest("POST", "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Delete ESXi cluster entry", func() {
		Context("Delete ESXi cluster by valid ID from data store", func() {
			It("Should Delete ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(
					esxiClusterController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/esxi-cluster/f3c6a763-51cd-436c-a828-c2ce6964c823", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Try to delete ESXi cluster by non-existent ID from data store", func() {
			It("Should fail to delete ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(
					esxiClusterController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/esxi-cluster/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
})
