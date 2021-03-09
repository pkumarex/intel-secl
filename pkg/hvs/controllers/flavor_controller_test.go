/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

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
)

var _ = Describe("FlavorController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks.MockFlavorStore
	var flavorController *controllers.FlavorController
	var hostStore *mocks.MockHostStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostTrustManager *smocks.MockHostTrustManager
	var hostStatusStore *mocks.MockHostStatusStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController controllers.HostController
	var hostControllerConfig domain.HostControllerConfig
	var hostConnectorProvider mocks2.MockHostConnectorFactory

	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		flavorStore = mocks.NewMockFlavorStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		certStore := mocks.NewFakeCertificatesStore()
		tagCertStore := mocks.NewMockTagCertificateStore()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()

		// init hostControllerConfig
		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, _ := base64.StdEncoding.DecodeString(dekBase64)
		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     dek,
			Username:              "fakeuser",
			Password:              "fakepassword",
		}

		hostController = controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}

		flavorController = &controllers.FlavorController{
			FStore:    flavorStore,
			FGStore:   flavorGroupStore,
			HStore:    hostStore,
			CertStore: certStore,
			TCStore:   tagCertStore,
			HTManager: hostTrustManager,
			HostCon:   hostController,
		}
	})
	// Specs for HTTP Get to "/flavors"
	Describe("Search Flavors", func() {
		Context("When no filter arguments are passed", func() {
			It("All Flavors records are returned", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).ToNot(HaveOccurred())
				//TODO Requires changes in mock flavor search method for this criteria
				Expect(len(sfs.SignedFlavors)).To(Equal(0))
			})
		})
		Context("When filtered by Flavor id", func() {
			It("Should get a single flavor entry", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?id=c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(sfs.SignedFlavors)).To(Equal(1))
			})
		})
		Context("When filtered by Flavor meta description key-value pair", func() {
			It("Should get a single flavor entry", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?key=bios_name&&value=Intel Corporation", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).NotTo(HaveOccurred())
				//TODO Requires changes in mock flavor search method for this criteria
				Expect(len(sfs.SignedFlavors)).To(Equal(0))
			})
		})
	})

	// Specs for HTTP Get to "/flavors/{flavor_id}"
	Describe("Retrieve Flavor", func() {
		Context("Retrieve Flavor by valid ID from data store", func() {
			It("Should retrieve Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve Flavor(created by template) by valid ID from data store", func() {
			It("Should retrieve Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors/e6612219-bbd5-4259-8c7e-991e43729a86", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Try to retrieve Flavor by non-existent ID from data store", func() {
			It("Should fail to retrieve Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))

				var sfs []*hvs.SignedFlavor
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).To(HaveOccurred())
				Expect(sfs).To(BeNil())
			})
		})
	})

	// Specs for HTTP Delete to "/flavors/{flavorId}"
	Describe("Delete Flavor by ID", func() {
		Context("Delete Flavor by ID from data store", func() {
			It("Should delete Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete Flavor by invalid ID from data store", func() {
			It("Should fail to delete Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavors/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Post to "/flavor"
	Describe("Create a new flavor", func() {
		Context("Provide a invalid Create request with XSS Attack Strings", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				flavorJson := `{ 
                              "connection_string": "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//–>\">'>",
                              "tls_policy_id": "TRUST_FIRST_CERTIFICATE",
                              "flavorgroup_name": "",
                              "partial_flavor_types": [
                                 "PLATFORM",
                                 "OS",
                                 "SOFTWARE",
                                 "HOST_UNIQUE"
                              ]}`
				req, err := http.NewRequest(
					"POST",
					"/flavors",
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

		Context("Provide a Create request without Accept header", func() {
			It("Should return 415 response code", func() {
				flavorJson := `{
						"connection_string": "intel:https://another.ta.ip.com:1443",
						"partial_flavor_types": [
							"PLATFORM",
							"OS",
							"HOST_UNIQUE",
							"SOFTWARE"
						]
					}`
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a Create request without Content-Type header", func() {
			It("Should return 415 response code", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				flavorJson := `{
						"connection_string": "intel:https://another.ta.ip.com:1443",
						"partial_flavor_types": [
							"PLATFORM",
							"OS",
							"HOST_UNIQUE",
							"SOFTWARE"
						]
					}`
				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(flavorJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a empty create request", func() {
			It("Should return 415 response code", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(""),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a valid manually crafted Flavor request", func() {
			It("Should return 201 Response code and a signed flavor", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				flavorJson := `{
								"flavor_collection": {
									"flavors": [
										{
											"flavor": {
												"meta": {
													"description": {
														"flavor_part": "PLATFORM",
														"source": "myhost.example.com",
														"label": "ImportPlatformFlavor",
														"bios_name": "Intel Corporation",
														"bios_version": "SE5C620.86B.02.01.0009.092820190230",
														"tpm_version": "2.0",
														"tboot_installed": "true"
													},
													"vendor": "INTEL"
												},
												"bios": {
													"bios_name": "Intel Corporation",
													"bios_version": "SE5C620.86B.02.01.0009.092820190230"
												},
												"hardware": {
													"processor_info": "57 06 05 00 FF FB EB BF",
													"processor_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
													"feature": {
														"TXT": {
															"enabled": true
														},
														"TPM": {
															"enabled": true,
															"version": "2.0",
															"pcr_banks": [
																"SHA1",
																"SHA256"
															]
														}
													}
												},
												"pcrs": {
													"SHA1": {
														"pcr_0": {
															"value": "308c314172d79c8ed0c91d91eb6d6b78a2a451a0"
														},
														"pcr_17": {
															"value": "f0c4bc16f4ccc7e813ec562a26ac181264b6b453",
															"event": [
																{
																	"value": "bc6b1c2e40d0d37f0e9415670515f869c14e3fe1",
																	"label": "HASH_START",
																	"info": {
																		"ComponentName": "HASH_START",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "1fad8a10c0f5723017987a842a332d922ff559eb",
																	"label": "BIOSAC_REG_DATA",
																	"info": {
																		"ComponentName": "BIOSAC_REG_DATA",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "3c585604e87f855973731fea83e21fab9392d2fc",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
																	"label": "LCP_DETAILS_HASH",
																	"info": {
																		"ComponentName": "LCP_DETAILS_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
																	"label": "STM_HASH",
																	"info": {
																		"ComponentName": "STM_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "c49243843032f40ceabf7528f53b7c2cbf8e9355",
																	"label": "MLE_HASH",
																	"info": {
																		"ComponentName": "MLE_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														},
														"pcr_18": {
															"value": "86da61107994a14c0d154fd87ca509f82377aa30",
															"event": [
																{
																	"value": "a395b723712b3711a89c2bb5295386c0db85fe44",
																	"label": "SINIT_PUBKEY_HASH",
																	"info": {
																		"ComponentName": "SINIT_PUBKEY_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "3c585604e87f855973731fea83e21fab9392d2fc",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
																	"label": "LCP_AUTHORITIES_HASH",
																	"info": {
																		"ComponentName": "LCP_AUTHORITIES_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														}
													},
													"SHA256": {
														"pcr_0": {
															"value": "b8b8a376ab2cc30632b544aaee67b464a8bff184f1f09698fa5b7470074510b3"
														},
														"pcr_17": {
															"value": "412beb56e05525c9522aea6b47a2abe58cb8387e57a6ad434fddb0b4f4ee41eb",
															"event": [
																{
																	"value": "9a31321ff5d4e5699cc368a0684be901837db04b5dca532b805e5895a39e57e7",
																	"label": "HASH_START",
																	"info": {
																		"ComponentName": "HASH_START",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "19f34545cdbf9316036535e6732a349fbe4d85bb6f102523934ba215329293fb",
																	"label": "BIOSAC_REG_DATA",
																	"info": {
																		"ComponentName": "BIOSAC_REG_DATA",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
																	"label": "LCP_DETAILS_HASH",
																	"info": {
																		"ComponentName": "LCP_DETAILS_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
																	"label": "STM_HASH",
																	"info": {
																		"ComponentName": "STM_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "c78680644d8e0cf90174fc78f09b75c99cfd71367433a88ee259f743226f03ec",
																	"label": "MLE_HASH",
																	"info": {
																		"ComponentName": "MLE_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														},
														"pcr_18": {
															"value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
															"event": [
																{
																	"value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
																	"label": "SINIT_PUBKEY_HASH",
																	"info": {
																		"ComponentName": "SINIT_PUBKEY_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
																	"label": "LCP_AUTHORITIES_HASH",
																	"info": {
																		"ComponentName": "LCP_AUTHORITIES_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														}
													}
												}
											}
										}
									]
								},
								"flavorgroup_name": "custom-flavorgroup"
							}`
				req, err := http.NewRequest(
					"POST",
					"/flavors",
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
		Context("Provide a manually crafted Flavor request with an invalid field name", func() {
			It("Should return 400 Error code", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				flavorJson := `{
								"flavor_collection": {
									"flavors": [
										{
											"flavor": {
												"meta": {
													"description": {
														"flavor_part": "PLATFORM",
														"source": "myhost.example.com",
														"label": "ImportPlatformFlavor",
														"bios_name": "Intel Corporation",
														"bios_version": "SE5C620.86B.02.01.0009.092820190230",
														"tpm_version": "2.0",
														"tboot_installed": "true"
													},
													"vendor": "INTEL"
												},
												"bios": {
													"bios_name": "Intel Corporation",
													"bios_version": "SE5C620.86B.02.01.0009.092820190230"
												},
												"hardware": {
													"processor_info": "57 06 05 00 FF FB EB BF",
													"processor_flags": "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
													"feature": {
														"TXT": {
															"enabled": true
														},
														"TPM": {
															"enabled": true,
															"version": "2.0",
															"pcr_banks": [
																"SHA1",
																"SHA256"
															]
														}
													}
												},
												"pcrs": {
													"SHA1": {
														"pcr_0": {
															"value": "308c314172d79c8ed0c91d91eb6d6b78a2a451a0"
														},
														"pcr_17": {
															"value": "f0c4bc16f4ccc7e813ec562a26ac181264b6b453",
															"event": [
																{
																	"value": "bc6b1c2e40d0d37f0e9415670515f869c14e3fe1",
																	"label": "HASH_START",
																	"info": {
																		"ComponentName": "HASH_START",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "1fad8a10c0f5723017987a842a332d922ff559eb",
																	"label": "BIOSAC_REG_DATA",
																	"info": {
																		"ComponentName": "BIOSAC_REG_DATA",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "3c585604e87f855973731fea83e21fab9392d2fc",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
																	"label": "LCP_DETAILS_HASH",
																	"info": {
																		"ComponentName": "LCP_DETAILS_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
																	"label": "STM_HASH",
																	"info": {
																		"ComponentName": "STM_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "c49243843032f40ceabf7528f53b7c2cbf8e9355",
																	"label": "MLE_HASH",
																	"info": {
																		"ComponentName": "MLE_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														},
														"pcr_18": {
															"value": "86da61107994a14c0d154fd87ca509f82377aa30",
															"event": [
																{
																	"value": "a395b723712b3711a89c2bb5295386c0db85fe44",
																	"label": "SINIT_PUBKEY_HASH",
																	"info": {
																		"ComponentName": "SINIT_PUBKEY_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "3c585604e87f855973731fea83e21fab9392d2fc",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0cf169a95bd32a9a1dc4c3499ade207d30ab8895",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
																	"label": "LCP_AUTHORITIES_HASH",
																	"info": {
																		"ComponentName": "LCP_AUTHORITIES_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "274f929dbab8b98a7031bbcd9ea5613c2a28e5e6",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "ca96de412b4e8c062e570d3013d2fccb4b20250a",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														}
													},
													"SHA256": {
														"pcr_0": {
															"value": "b8b8a376ab2cc30632b544aaee67b464a8bff184f1f09698fa5b7470074510b3"
														},
														"pcr_17": {
															"value": "412beb56e05525c9522aea6b47a2abe58cb8387e57a6ad434fddb0b4f4ee41eb",
															"event": [
																{
																	"value": "9a31321ff5d4e5699cc368a0684be901837db04b5dca532b805e5895a39e57e7",
																	"label": "HASH_START",
																	"info": {
																		"ComponentName": "HASH_START",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "19f34545cdbf9316036535e6732a349fbe4d85bb6f102523934ba215329293fb",
																	"label": "BIOSAC_REG_DATA",
																	"info": {
																		"ComponentName": "BIOSAC_REG_DATA",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
																	"label": "LCP_DETAILS_HASH",
																	"info": {
																		"ComponentName": "LCP_DETAILS_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
																	"label": "STM_HASH",
																	"info": {
																		"ComponentName": "STM_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "c78680644d8e0cf90174fc78f09b75c99cfd71367433a88ee259f743226f03ec",
																	"label": "MLE_HASH",
																	"info": {
																		"ComponentName": "MLE_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														},
														"pcr_18": {
															"value": "d9e55bd1c570a6408fb1368f3663ae92747241fc4d2a3622cef0efadae284d75",
															"event": [
																{
																	"value": "da256395df4046319ef0af857d377a729e5bc0693429ac827002ffafe485b2e7",
																	"label": "SINIT_PUBKEY_HASH",
																	"info": {
																		"ComponentName": "SINIT_PUBKEY_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450",
																	"label": "CPU_SCRTM_STAT",
																	"info": {
																		"ComponentName": "CPU_SCRTM_STAT",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "d81fe96dc500bc43e1cd5800bef9d72b3d030bdb7e860e10c522e4246b30bd93",
																	"label": "OSSINITDATA_CAP_HASH",
																	"info": {
																		"ComponentName": "OSSINITDATA_CAP_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
																	"label": "LCP_AUTHORITIES_HASH",
																	"info": {
																		"ComponentName": "LCP_AUTHORITIES_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b",
																	"label": "NV_INFO_HASH",
																	"info": {
																		"ComponentName": "NV_INFO_HASH",
																		"EventName": "OpenSource.EventName"
																	}
																},
																{
																	"value": "27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67",
																	"label": "tb_policy",
																	"info": {
																		"ComponentName": "tb_policy",
																		"EventName": "OpenSource.EventName"
																	}
																}
															]
														}
													}
												}
											}
										}
									]
								},
								"invalid_field_name": ["custom-flavorgroup"]
							}`
				req, err := http.NewRequest(
					"POST",
					"/flavors",
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
})
