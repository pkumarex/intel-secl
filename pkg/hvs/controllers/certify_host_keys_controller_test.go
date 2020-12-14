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
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	wlaModel "github.com/intel-secl/intel-secl/v3/pkg/model/wlagent"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
)

var certStore *models.CertificatesStore

var _ = BeforeSuite(func() {
	//Generate Privacyca cert
	certStore = utils.LoadCertificates(mocks.NewFakeCertificatesPathStore())
	caCertDer, caKeyDer, _ := crypt.CreateKeyPairAndCertificate(consts.DefaultPrivacyCaIdentityIssuer, "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
	caCert, _ := x509.ParseCertificate(caCertDer)
	var caCerts []x509.Certificate
	caCerts = append(caCerts, *caCert)
	caKey, _ := x509.ParsePKCS8PrivateKey(caKeyDer)
	(*certStore)[models.CaCertTypesPrivacyCa.String()].Key = caKey
	(*certStore)[models.CaCertTypesPrivacyCa.String()].Certificates = caCerts
})

var _ = AfterSuite(func() {
	err := os.RemoveAll("../domain/mocks/resources/aik-reqs-dir")
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("CertifyHostKeysController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var ecStore mocks.MockTpmEndorsementStore
	var certifyHostKeysController *controllers.CertifyHostKeysController
	var aikcert []byte
	// modulus and aikName required for aik certificate generation
	modulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
	aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq")
	n := new(big.Int)
	n.SetBytes(modulus)
	aikPubKey := rsa.PublicKey{N: n, E: 65537}

	BeforeEach(func() {
		certifyHostAiksController := controllers.NewCertifyHostAiksController(certStore, &ecStore, 2, "")
		caKey := (*certStore)[models.CaCertTypesPrivacyCa.String()].Key
		caCert := &(*certStore)[models.CaCertTypesPrivacyCa.String()].Certificates[0]
		// Generate aik certificate
		var err error
		aikcert, err = certifyHostAiksController.CertifyAik(&aikPubKey, aikName, caKey.(*rsa.PrivateKey), caCert, 2)
		Expect(err).NotTo(HaveOccurred())
		router = mux.NewRouter()
		certifyHostKeysController = controllers.NewCertifyHostKeysController(certStore)
	})

	Describe("Create Binding key certificate", func() {
		Context("Provide valid data in request", func() {
			It("Return Binding key certificate", func() {

				router.Handle("/rpc/certify-host-binding-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifyBindingKey))).Methods("POST")

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("AJH/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8Rk")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					"POST",
					"/rpc/certify-host-binding-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})

		Context("Provide invalid data in request", func() {
			It("Should get HTTP Status: 400", func() {

				router.Handle("/rpc/certify-host-binding-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifyBindingKey))).Methods("POST")

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8Rk")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					"POST",
					"/rpc/certify-host-binding-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})

	Describe("Create Signing key certificate", func() {
		Context("Provide valid data in request", func() {
			It("Return Signing key certificate", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods("POST")

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("AJH/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					"POST",
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})

		Context("Provide invalid tpmCertifyKey in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods("POST")

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					"POST",
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide invalid aikcert in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods("POST")

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				aikcert = append(aikcert, []byte{0x03, 0x04}...)
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					"POST",
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
})
