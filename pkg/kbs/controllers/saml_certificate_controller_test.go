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

var _ = Describe("SamlCertController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var certStore *mocks.MockCertificateStore
	var samlCertController *controllers.CertificateController

	validSamlCert, _ := ioutil.ReadFile(samlCertsDir + "saml_cert.pem")
	invalidSamlCert := strings.Replace(strings.Replace(string(validSamlCert), "-----BEGIN CERTIFICATE-----\n", "", 2), "-----END CERTIFICATE-----", "", 2)

	BeforeEach(func() {
		router = mux.NewRouter()
		certStore = mocks.NewFakeCertificateStore()
		samlCertController = controllers.NewCertificateController(certStore)
	})

	// Specs for HTTP Post to "/saml-certificates"
	Describe("Import SamlCertificates", func() {
		Context("Provide a valid SamlCertificate in request", func() {
			It("Should import a new SamlCertificate", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Import))).Methods("POST")

				// Import Request body
				importCertReq := string(validSamlCert)

				req, err := http.NewRequest(
					"POST",
					"/saml-certificates",
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

		Context("Provide a SamlCertificate without CERTIFICATE headers in request", func() {
			It("Should fail to import SamlCertificate", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Import))).Methods("POST")

				// Import Request body
				importCertReq := invalidSamlCert

				req, err := http.NewRequest(
					"POST",
					"/saml-certificates",
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

		Context("Provide a SamlCertificate without DER data in request", func() {
			It("Should fail to import SamlCertificate", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Import))).Methods("POST")

				// Import Request body
				importCertReq := `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`

				req, err := http.NewRequest(
					"POST",
					"/saml-certificates",
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

	// Specs for HTTP GET to "/saml-certificates/{id}"
	Describe("Retrieve an existing SamlCertificate", func() {
		Context("Retrieve SamlCertificate by ID", func() {
			It("Should retrieve a SamlCertificate", func() {
				router.Handle("/saml-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(samlCertController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve SamlCertificate by non-existent ID", func() {
			It("Should fail to retrieve SamlCertificate", func() {
				router.Handle("/saml-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(samlCertController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates/c00135a8-f5e9-4860-ae6c-4acce525d340", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP DELETE to "/saml-certificates/{id}"
	Describe("Delete an existing SamlCertificate", func() {
		Context("Delete SamlCertificate by ID", func() {
			It("Should delete a SamlCertificate", func() {
				router.Handle("/saml-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(samlCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/saml-certificates/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Delete SamlCertificate by non-existent ID", func() {
			It("Should fail to delete SamlCertificate", func() {
				router.Handle("/saml-certificates/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(samlCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/saml-certificates"+"/c00135a8-f5e9-4860-ae6c-4acce525d340", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/saml-certificates"
	Describe("Search SamlCertificates", func() {
		Context("When no query parameters are passed", func() {
			It("Should get list of all the SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates", nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?badparam=value", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid SubjectEqualTo", func() {
			It("Should get a list of SamlCertificates whose Subject is SubjectEqualTo value", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?subjectEqualTo=mtwilson-saml", nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?subjectEqualTo=mtwilson<>saml", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid SubjectContains", func() {
			It("Should get a list of SamlCertificates whose Subject contains the SubjectContains value", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?subjectContains=-saml", nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?subjectContains=<>saml", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid IssuerEqualTo", func() {
			It("Should get a list of SamlCertificates filtered whose Issuer is IssuerEqualTo value", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?issuerEqualTo=CMS Signing CA", nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?issuerEqualTo=CMS<>Signing<>CA", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid IssuerContains", func() {
			It("Should get a list of SamlCertificates whose Issuer contains the IssuerContains value", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?issuerContains=Signing CA", nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?issuerContains=Signing<>CA", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by a valid ValidOn date", func() {
			It("Should get a list of SamlCertificates which are valid on the ValidOn date", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?validOn="+time.Now().Format(time.RFC3339), nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?validOn="+time.Now().Format(time.RFC3339)+"0000000000000", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by valid ValidBefore date", func() {
			It("Should get a list of SamlCertificates which are valid before the ValidBefore date", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?validBefore="+time.Now().AddDate(-1, 0, 0).Format(time.RFC3339), nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?validBefore="+time.Now().Format(time.RFC3339)+"01010101010", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by valid ValidAfter date", func() {
			It("Should get a list of SamlCertificates which are valid after the ValidAfter date", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?validAfter="+time.Now().AddDate(1, 0, 0).Format(time.RFC3339), nil)
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
			It("Should fail to get SamlCertificates", func() {
				router.Handle("/saml-certificates", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(samlCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/saml-certificates?validAfter="+time.Now().Format(time.RFC3339)+"ABC", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
