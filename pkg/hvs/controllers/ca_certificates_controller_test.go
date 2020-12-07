/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("CaCertificatesController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	certStore := utils.LoadCertificates(mocks2.NewFakeCertificatesPathStore())
	var caCertificatesController *controllers.CaCertificatesController
	BeforeEach(func() {
		router = mux.NewRouter()
		caCertificatesController = &controllers.CaCertificatesController{CertStore: certStore}
	})

	// Specs for HTTP Post to "/ca-certificates"
	Describe("Create root CA certificates", func() {
		Context("Create root CA certificates", func() {
			It("Should create CA certificates with CN", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods("POST")
				cert, _, _ := crypt.CreateKeyPairAndCertificate("root-test", "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
				certificate := hvs.CaCertificate{
					Name: 	     "root-test",
					Type:        models.CaCertTypesRootCa.String(),
					Certificate: cert,
				}
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					"POST",
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Context("Create root CA certificates with invalid certificate type", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods("POST")
				certificate := hvs.CaCertificate{
					Name: 	     "root-test",
					Type:        models.CaCertTypesTagCa.String(),
				}
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					"POST",
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Create root CA certificates with invalid payload", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods("POST")
				certificate := ""
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					"POST",
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Create root CA certificates with empty body", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods("POST")
				req, err := http.NewRequest(
					"POST",
					"/ca-certificates",
					nil,
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

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get Endorsement CA certificates", func() {
		Context("Get all Endorsement CA certificates with search endorsement", func() {
			It("Should get list of Endorsement CA certificates", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates?domain=endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
		Context("Get all Endorsement CA certificates", func() {
			It("Should get list of Endorsement CA certificates with search ek", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates?domain=ek", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
		Context("Get certificates with invalid domain", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates?domain=dumb", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get SAML certificates", func() {
		Context("Get all SAML certificates", func() {
			It("Should get list of SAML certificates with associated CA", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates?domain=saml", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
	})

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get SAML certificate", func() {
		Context("Get SAML certificate", func() {
			It("Should get SAML certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/saml", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
		Context("Get certificate with invalid type", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/dumb", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get Privacy CA certificate", func() {
		Context("Get all Privacy CA certificate with keyword privacy", func() {
			It("Should get Privacy CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/privacy", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Context("Get all Privacy CA certificate with keyword aik", func() {
			It("Should get Privacy CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/aik", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get Endorsement CA certificate", func() {
		Context("Get all Endorsement CA certificate with keyword endorsement", func() {
			It("Should get Endorsement CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Context("Get all Endorsement CA certificate with keyword ek", func() {
			It("Should get Endorsement CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/ek", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get TLS certificate", func() {
		Context("Get TLS certificate", func() {
			It("Should get TLS certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/ca-certificates/tls", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
