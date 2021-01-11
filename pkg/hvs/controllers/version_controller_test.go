/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("VersionController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var versionController *controllers.VersionController
	BeforeEach(func() {
		router = mux.NewRouter()
		versionController = &controllers.VersionController{}
	})

	// Specs for HTTP Get to "/version"
	Describe("Get Version", func() {
		Context("Get version details", func() {
			It("Should return version", func() {
				router.Handle("/version", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(versionController.GetVersion))).Methods("GET")
				req, err := http.NewRequest("GET", "/version", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var version string
				version = string(w.Body.Bytes())
				Expect(version).NotTo(Equal(""))
			})
		})
	})

})
