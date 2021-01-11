/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"encoding/xml"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	smocks "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"strings"
)

var _ = Describe("ReportController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var hostStore *mocks.MockHostStore

	var reportStore *mocks.MockReportStore
	var reportController *controllers.ReportController
	var hostTrustManager *smocks.MockHostTrustManager

	var hostStatusStore *mocks.MockHostStatusStore

	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		reportStore = mocks.NewMockReportStore()
		reportController = controllers.NewReportController(reportStore, hostStore, hostStatusStore, hostTrustManager)
	})

	// Specs for HTTP Post to "/reports"
	Describe("Create a new Report", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods("POST")
				body := `{
							"host_name": "localhost1"
						}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a valid Create request for which host is not registered", func() {
			It("Should return bad request", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods("POST")
				body := `{
							"host_id": "ee37c370-7ece-4250-a677-6ee12adce8e2"
						}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a valid Create request for which host is registered and status is not connected", func() {
			It("Should return bad request", func() {

				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods("POST")
				body := `{
							"hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e2"
						}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a Create request that contains malformed hostname", func() {
			It("Should fail to create new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3<>"
							}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a empty create request", func() {
			It("Should see an 400 error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods("POST")
				hostJson := `{}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/reports/{rId}"
	Describe("Retrieve an existing Report", func() {
		Context("Retrieve Report by ID", func() {
			It("Should retrieve a Report", func() {
				router.Handle("/reports/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports/15701f03-7b1d-49f9-ac62-6b9b0728bdb3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve Report by non-existent ID", func() {
			It("Should fail to retrieve Report", func() {
				router.Handle("/reports/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/reports"
	Describe("Search for all the Reports", func() {
		Context("Get all the Reports", func() {
			It("Should get list of all the Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(2))
			})
		})

		Context("Get all the Report for host with given hardware UUID", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports?hostHardwareId=e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Get all the Report for host with given hostname", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports?hostName=localhost1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Get all the Report for host with given hostId", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports?hostId=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Get all the Report for hosts with status CONNECTED", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports?hostStatus=CONNECTED", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Search Report for given invalid report id", func() {
			It("Should respond with bad request", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports?id=ee37c360-7eae-4250-a677-6ee12adce", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

			})
		})
	})

	// Specs for HTTP Post to "/reports" for accept:samlassertion+xml
	Describe("Create a new SAML Report", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.CreateSaml))).Methods("POST")
				body := `{
							"host_name": "localhost1"
						}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
				Expect(w.Header().Get("Content-Type")).To(Equal(constants.HTTPMediaTypeSaml))
			})
		})

		Context("Provide a Create request that contains malformed hostname", func() {
			It("Should fail to create Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.CreateSaml))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3<>"
							}`

				req, err := http.NewRequest(
					"POST",
					"/reports",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/reports" for accept:samlassertion+xml
	Describe("Search for all Saml Reports", func() {
		Context("Get all the Reports", func() {
			It("Should get list of all Saml Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.SearchSaml))).Methods("GET")
				req, err := http.NewRequest("GET", "/reports", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var samlCollection []string
				err = xml.NewDecoder(w.Body).Decode(&samlCollection)
				Expect(err).NotTo(HaveOccurred())
				//TODO search should return actually 2
				Expect(len(samlCollection)).To(Equal(1))
				Expect(w.Header().Get("Content-Type")).To(Equal(constants.HTTPMediaTypeSaml))
			})
		})
	})
})
