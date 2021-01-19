/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"net/http"
	"net/http/httptest"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertifyHostAiksController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var certifyHostAiksController *controllers.CertifyHostAiksController
	var cacert *x509.Certificate
	ecStore := mocks.MockTpmEndorsementStore{}

	BeforeEach(func() {
		router = mux.NewRouter()
		cacert = &(*certStore)[models.CaCertTypesPrivacyCa.String()].Certificates[0]
		certifyHostAiksController = controllers.NewCertifyHostAiksController(certStore, &ecStore, 2, "../domain/mocks/resources/aik-reqs-dir/")
	})

	Describe("Create Identity Proof request", func() {
		Context("Provide valid data in request", func() {
			It("Return Identity Proof request", func() {

				router.Handle("/privacyca/identity-challenge-request", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequest
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					AikModulus:           aikModulus,
					AikName:              aikName,
				}

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				ekCertBytes, _ := base64.StdEncoding.DecodeString("MIIEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				// Get the Identity challenge request
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				jsonData, _ := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-request",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})

		Context("ek root ca not present in endorsement certificate and ek cert is registered", func() {
			It("Return Identity Proof request", func() {
				// mockEndorsement is having the ekcert
				mockEndorsement := mocks.NewFakeTpmEndorsementStore()
				certifyHostAiksController = controllers.NewCertifyHostAiksController(certStore, mockEndorsement, 2, "../domain/mocks/resources/aik-reqs-dir/")
				router.Handle("/privacyca/identity-challenge-request", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequest
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					AikModulus:           aikModulus,
					AikName:              aikName,
				}

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				ekCertBytes, _ := base64.StdEncoding.DecodeString("MIID3DCCA4GgAwIBAgILALfUewXBMLJq9oQwCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMYTnV2b3RvbiBUUE0gUm9vdCBDQSAxMTEwMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTgwNDMwMDkwOTQyWhcNMzgwNDI2MDkwOTQyWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsLVF8PTReeg3wX7/8ia6mzsHmz6uU2gNATYDfD+BD138oZoEokfvyNEwmcgl4946ABBEi7equO3Xg7GzoBbZko2g4nL8B7bTUGldMLR/D2CKxmRKnN6aTNp0k+PTk7Kg/Q/rdc3ANxseW4z5MPKVais1pCflHLrfatrTKvfob3WrhFpTzvxP4N4NdrQ0QWsezreRi6RwbmKyuUTCUryt8KNvQ6+jnR0jK7zYW6fHbwwHWNHMfGP/E3CSVrdje/gqUXyWKPRIBLcOuYKA82UPoB9dP+/lc5K7yaTRdRRvR0x07XqORva4Y0f+K6uDxkfs9uiOFyjcnW/L/E/gMyyc4QIDAQABo4IBwDCCAbwwSgYDVR0RAQH/BEAwPqQ8MDoxODAUBgVngQUCARMLaWQ6NEU1NDQzMDAwEAYFZ4EFAgITB05QQ1Q2eHgwDgYFZ4EFAgMTBWlkOjEzMAwGA1UdEwEB/wQCMAAwEAYDVR0lBAkwBwYFZ4EFCAEwHwYDVR0jBBgwFoAUFZHUtur5jQEEhktpA6SN0AJgd9MwDgYDVR0PAQH/BAQDAgUgMHAGA1UdCQRpMGcwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwTQYFZ4EFAhIxRDBCAgEAAQH/oAMKAQGhAwoBAKIDCgEAoxUwExYDMy4xCgEECgEBAQH/oAMKAQKkDzANFgUxNDAtMgoBAgEBAKUDAQEAMEEGA1UdIAQ6MDgwNgYEVR0gADAuMCwGCCsGAQUFBwIBFiBodHRwOi8vd3d3Lm51dm90b24uY29tL3NlY3VyaXR5LzBoBggrBgEFBQcBAQRcMFowWAYIKwYBBQUHMAKGTGh0dHA6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJpdHkvTlRDLVRQTS1FSy1DZXJ0L051dm90b24gVFBNIFJvb3QgQ0EgMTExMC5jZXIwCgYIKoZIzj0EAwIDSQAwRgIhAIZW5ub47c5tw7JFhMH7X9LBYKuk5wPYmV8NMLPz3W2qAiEAgo9he9tU504eatKnvOmL97DnKPlc8qTgev0v9dx1wM4=")
				// Get the Identity challenge request
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				jsonData, _ := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-request",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})

		Context("ek root ca not present in endorsement certificate and ek cert is not registered", func() {
			It("Should get HTTP Status: 400 ", func() {
				router.Handle("/privacyca/identity-challenge-request", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequest
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					AikModulus:           aikModulus,
					AikName:              aikName,
				}

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				ekCertBytes, _ := base64.StdEncoding.DecodeString("MIID3DCCA4GgAwIBAgILALfUewXBMLJq9oQwCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMYTnV2b3RvbiBUUE0gUm9vdCBDQSAxMTEwMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTgwNDMwMDkwOTQyWhcNMzgwNDI2MDkwOTQyWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsLVF8PTReeg3wX7/8ia6mzsHmz6uU2gNATYDfD+BD138oZoEokfvyNEwmcgl4946ABBEi7equO3Xg7GzoBbZko2g4nL8B7bTUGldMLR/D2CKxmRKnN6aTNp0k+PTk7Kg/Q/rdc3ANxseW4z5MPKVais1pCflHLrfatrTKvfob3WrhFpTzvxP4N4NdrQ0QWsezreRi6RwbmKyuUTCUryt8KNvQ6+jnR0jK7zYW6fHbwwHWNHMfGP/E3CSVrdje/gqUXyWKPRIBLcOuYKA82UPoB9dP+/lc5K7yaTRdRRvR0x07XqORva4Y0f+K6uDxkfs9uiOFyjcnW/L/E/gMyyc4QIDAQABo4IBwDCCAbwwSgYDVR0RAQH/BEAwPqQ8MDoxODAUBgVngQUCARMLaWQ6NEU1NDQzMDAwEAYFZ4EFAgITB05QQ1Q2eHgwDgYFZ4EFAgMTBWlkOjEzMAwGA1UdEwEB/wQCMAAwEAYDVR0lBAkwBwYFZ4EFCAEwHwYDVR0jBBgwFoAUFZHUtur5jQEEhktpA6SN0AJgd9MwDgYDVR0PAQH/BAQDAgUgMHAGA1UdCQRpMGcwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwTQYFZ4EFAhIxRDBCAgEAAQH/oAMKAQGhAwoBAKIDCgEAoxUwExYDMy4xCgEECgEBAQH/oAMKAQKkDzANFgUxNDAtMgoBAgEBAKUDAQEAMEEGA1UdIAQ6MDgwNgYEVR0gADAuMCwGCCsGAQUFBwIBFiBodHRwOi8vd3d3Lm51dm90b24uY29tL3NlY3VyaXR5LzBoBggrBgEFBQcBAQRcMFowWAYIKwYBBQUHMAKGTGh0dHA6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJpdHkvTlRDLVRQTS1FSy1DZXJ0L051dm90b24gVFBNIFJvb3QgQ0EgMTExMC5jZXIwCgYIKoZIzj0EAwIDSQAwRgIhAIZW5ub47c5tw7JFhMH7X9LBYKuk5wPYmV8NMLPz3W2qAiEAgo9he9tU504eatKnvOmL97DnKPlc8qTgev0v9dx1wM4=")
				// Get the Identity challenge request
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				jsonData, _ := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-request",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide invalid ekcert in request", func() {
			It("Should get HTTP Status: 400", func() {

				router.Handle("/privacyca/identity-challenge-request", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge))).Methods("POST")

				//// Mock TA Flow for generating data for identityChallengeRequest
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikName, _ := base64.StdEncoding.DecodeString("afefAAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRffdfA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					AikModulus:           aikModulus,
					AikName:              aikName,
				}

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				ekCertBytes, err := base64.StdEncoding.DecodeString("MCDEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				Expect(err).NotTo(HaveOccurred())
				// Get the Identity challenge request
				identityChallengeRequest, _ = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				jsonData, err := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-request",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})

	Describe("Create Identity Proof request response", func() {
		Context("Provide valid data in request", func() {
			It("Return Identity Proof request response", func() {
				router.Handle("/privacyca/identity-challenge-response", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequestReponse
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					AikModulus:           aikModulus,
					AikName:              aikName,
				}

				ekCertBytes, _ := base64.StdEncoding.DecodeString("MIIEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				identityRequestChallenge, _ := crypt.GetRandomBytes(32)

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(identityRequestChallenge, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				// This step is usually performed by HVS for verifying identityRequestChallenge that gets created during
				// TA on requesting /rpc/identity-request-challenge api for given ekcert
				certifyHostAiksController.StoreEkCerts(identityRequestChallenge, ekCertBytes, identityChallengeRequest)
				jsonData, err := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-response",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})

		Context("Provide invalid ekcert in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/privacyca/identity-challenge-response", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequestReponse
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					AikModulus:           aikModulus,
					AikName:              aikName,
				}

				ekCertBytes, _ := base64.StdEncoding.DecodeString("MDCEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				identityRequestChallenge, _ := crypt.GetRandomBytes(32)
				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(identityRequestChallenge, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				// This step is usually performed by HVS for verifying identityRequestChallenge that gets created during
				// TA on requesting /rpc/identity-request-challenge api for given ekcert
				certifyHostAiksController.StoreEkCerts(identityRequestChallenge, ekCertBytes, identityChallengeRequest)
				jsonData, err := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-response",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
})
