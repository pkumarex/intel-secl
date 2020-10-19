/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/mocks"
	kbsRoutes "github.com/intel-secl/intel-secl/v3/pkg/kbs/router"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TpmIdentityCertController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var certStore *mocks.MockCertificateStore
	var tpmIdentityCertController *controllers.CertificateController

	validTpmCert, _ := ioutil.ReadFile(tpmIdentityCertsDir + "privacyca_cert.pem")
	invalidTpmCert := strings.Replace(strings.Replace(string(validTpmCert), "-----BEGIN CERTIFICATE-----\n", "", 1), "-----END CERTIFICATE-----", "", 1)

	BeforeEach(func() {
		router = mux.NewRouter()
		certStore = mocks.NewFakeCertificateStore()
		tpmIdentityCertController = controllers.NewCertificateController(certStore)
	})

	// Specs for HTTP Post to "/tpm-identity-certificates"
	Describe("Import TpmIdentityCertificates", func() {
		Context("Provide a valid TpmIdentityCertificate in request", func() {
			It("Should import a new TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Import))).Methods("POST")

				// Import Request body
				importCertReq := string(validTpmCert)

				req, err := http.NewRequest(
					"POST",
					"/tpm-identity-certificates",
					strings.NewReader(importCertReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a TpmIdentityCertificate without CERTIFICATE headers in request", func() {
			It("Should fail to import TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Import))).Methods("POST")

				// Import Request body
				importCertReq := invalidTpmCert

				req, err := http.NewRequest(
					"POST",
					"/tpm-identity-certificates",
					strings.NewReader(importCertReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a TpmIdentityCertificate without DER data in request", func() {
			It("Should fail to import TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Import))).Methods("POST")

				// Import Request body
				importCertReq := `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`

				req, err := http.NewRequest(
					"POST",
					"/tpm-identity-certificates",
					strings.NewReader(importCertReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP GET to "/tpm-identity-certificates/{id}"
	Describe("Retrieve an existing TpmIdentityCertificate", func() {
		Context("Retrieve TpmIdentityCertificate by ID", func() {
			It("Should retrieve a TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(tpmIdentityCertController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve TpmIdentityCertificate by non-existent ID", func() {
			It("Should fail to retrieve TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(tpmIdentityCertController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates/c00135a8-f5e9-4860-ae6c-4acce525d340", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP DELETE to "/tpm-identity-certificates/{id}"
	Describe("Delete an existing TpmIdentityCertificate", func() {
		Context("Delete TpmIdentityCertificate by ID", func() {
			It("Should delete a TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(tpmIdentityCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/tpm-identity-certificates/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Delete TpmIdentityCertificate by non-existent ID", func() {
			It("Should fail to delete TpmIdentityCertificate", func() {
				router.Handle("/tpm-identity-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(tpmIdentityCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/tpm-identity-certificates"+"/c00135a8-f5e9-4860-ae6c-4acce525d340", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/tpm-identity-certificates"
	Describe("Search TpmIdentityCertificates", func() {
		Context("When no query parameters are passed", func() {
			It("Should get list of all the TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(certs)).To(Equal(2))
			})
		})

		Context("When unknown query parameters are passed", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?badparam=value", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid SubjectEqualTo", func() {
			It("Should get a list of TpmIdentityCertificates whose Subject is SubjectEqualTo value", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?subjectEqualTo=HVS Privacy Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(certs)).To(Equal(1))
			})
		})

		Context("When filtered by an invalid SubjectEqualTo", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?subjectEqualTo=HVS<>Privacy<>Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid SubjectContains", func() {
			It("Should get a list of TpmIdentityCertificates whose Subject contains the SubjectContains value", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?subjectContains=Privacy Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(certs)).To(Equal(1))
			})
		})

		Context("When filtered by an invalid SubjectContains", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?subjectContains=Privacy<>Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid IssuerEqualTo", func() {
			It("Should get a list of TpmIdentityCertificates filtered whose Issuer is IssuerEqualTo value", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?issuerEqualTo=HVS Privacy Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(certs)).To(Equal(1))
			})
		})

		Context("When filtered by an invalid IssuerEqualTo", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?issuerEqualTo=HVS<>Privacy<>Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid IssuerContains", func() {
			It("Should get a list of TpmIdentityCertificates whose Issuer contains the IssuerContains value", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?issuerContains=Privacy Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(certs)).To(Equal(1))
			})
		})

		Context("When filtered by an invalid IssuerContains", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?issuerContains=Privacy<>Certificate", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid ValidOn date", func() {
			It("Should get a list of TpmIdentityCertificates which are valid on the ValidOn date", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?validOn="+time.Now().Format(time.RFC3339), nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(certs)).To(Equal(2))
			})
		})

		Context("When filtered by invalid ValidOn date", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?validOn="+time.Now().Format(time.RFC3339)+"0000000000000", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by valid ValidBefore date", func() {
			It("Should get a list of TpmIdentityCertificates which are valid before the ValidBefore date", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?validBefore="+time.Now().AddDate(-1, 0, 0).Format(time.RFC3339), nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(certs)).To(Equal(0))
			})
		})

		Context("When filtered by invalid ValidBefore date", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?validBefore="+time.Now().Format(time.RFC3339)+"01010101010", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by valid ValidAfter date", func() {
			It("Should get a list of TpmIdentityCertificates which are valid after the ValidAfter date", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?validAfter="+time.Now().AddDate(1, 0, 0).Format(time.RFC3339), nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var certs []kbs.Certificate
				err = json.Unmarshal(w.Body.Bytes(), &certs)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(certs)).To(Equal(0))
			})
		})

		Context("When filtered by invalid ValidAfter date", func() {
			It("Should fail to get TpmIdentityCertificates", func() {
				router.Handle("/tpm-identity-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(tpmIdentityCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-identity-certificates?validAfter="+time.Now().Format(time.RFC3339)+"ABC", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
