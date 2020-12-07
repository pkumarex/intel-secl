/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package vs

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/aas"
)

var SampleSamlReportPath = "../../ihub/test/resources/saml_report.xml"

//AASToken token for AAS
var AASToken = "eyJhbGciOiJSUzM4NCIsImtpZCI6ImU5NjI1NzI0NTUwNzMwZGI3N2I2YmEyMjU1OGNjZTEyOTBkNjRkNTciLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyUm9sZU1hbmFnZXIifSx7InNlcnZpY2UiOiJUQSIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn0seyJzZXJ2aWNlIjoiVlMiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IktNUyIsIm5hbWUiOiJLZXlDUlVEIn0seyJzZXJ2aWNlIjoiQUgiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IldMUyIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn1dLCJwZXJtaXNzaW9ucyI6W3sic2VydmljZSI6IkFIIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiS01TIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiVEEiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJWUyIsInJ1bGVzIjpbIio6KjoqIl19LHsic2VydmljZSI6IldMUyIsInJ1bGVzIjpbIio6KjoqIl19XSwiZXhwIjoxNTk0NDgxMjAxLCJpYXQiOjE1OTQ0NzQwMDEsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiZ2xvYmFsX2FkbWluX3VzZXIifQ.euPkZEv0P9UC8ni05hb5wczFa9_C2G4mNAl4nVtBQ0oS-00qK4wC52Eg1UZqAjkVWXafHRcEjjsdQHs1LtjECFmU6zUNOMEtLLIOZwhnD7xlHkC-flpzLMT0W5162nsW4xSp-cF-r_05C7PgFcK9zIfMtn6_MUMcxlSXkX21AJWwfhVfz4ogEY2mqt73Ramd1tvhGbsz7i3XaljnopSTV7djNMeMZ33MPzJYGl5ph_AKBZwhBTA0DV3JAPTE9jXqrhtOG1iR1yM9kHChskzxAaRDm0v3V07ySgkxyv7dAzMW5Ek_NGCulyjP5N_WgSeuTkw26A8kZpSrNRWdbnyOr_EZ4y6wDX9GMARrR4PyTb6hU9x3ejahxs3L_Z7BzbYpO4WF1CvlYl5BoH71PnFPNKMkvbIFv1XcLPwKeLQpohEOr7zEN4EeltjpqBGCgiCFz4vHu5rk2iFCu1JJPDTVR3jJplJRZgCFiwsh42R3oomP-q43k8_PPLIMjaxAADgd"

func mockServer(t *testing.T) (*http.Server, string) {
	router := mux.NewRouter()

	router.HandleFunc("/aas/token", func(w http.ResponseWriter, router *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(AASToken))
	}).Methods("POST")

	router.HandleFunc("/mtwilson/v2/reports", func(w http.ResponseWriter, router *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		samlReport, err := ioutil.ReadFile(SampleSamlReportPath)
		if err != nil {
			t.Log("vs/client_test:mockServer(): Unable to read file", err)
		}
		w.Write([]byte(samlReport))
	}).Methods("GET")

	return serveController(t, router)

}

func serveController(t *testing.T, handler http.Handler) (*http.Server, string) {
	//Listener Implementations
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Log("vs/client_test:ServeController() : Unable to initiate Listener", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	err = listener.Close()
	if err != nil {
		t.Log("vs/client_test:ServeController() : Unable to close Listener", err)
	}
	portString := fmt.Sprintf(":%d", port)

	httpSer := &http.Server{
		Addr:    portString,
		Handler: handler,
	}
	go httpSer.ListenAndServe()

	return httpSer, portString
}

func TestClient_GetCaCerts(t *testing.T) {
	server, portString := mockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()
	aasUrl, _ := url.Parse("http://localhost" + portString + "/aas")
	baseURL, _ := url.Parse("http://localhost" + portString + "/mtwilson/v2")

	client1 := Client{
		AASURL:    aasUrl,
		BaseURL:   baseURL,
		Password:  "admin@ihub",
		UserName:  "hubadminpass",
		CertArray: []x509.Certificate{},
	}

	type args struct {
		domain string
	}
	tests := []struct {
		name    string
		c       Client
		args    args
		wantErr bool
	}{
		{
			name:    "Test 1 Negative Case",
			c:       client1,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.c.GetCaCerts(tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetCaCerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestClient_GetSamlReports(t *testing.T) {
	server, portString := mockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()

	aasUrl, _ := url.Parse("http://localhost" + portString + "/aas")
	baseURL, _ := url.Parse("http://localhost" + portString + "/mtwilson/v2")

	client1 := Client{
		AASURL:    aasUrl,
		BaseURL:   baseURL,
		Password:  "admin@ihub",
		UserName:  "hubadminpass",
		CertArray: []x509.Certificate{},
	}
	fmt.Println(client1)
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		c       Client
		args    args
		wantErr bool
	}{
		{
			name:    "Test 1 Positive Case",
			c:       client1,
			wantErr: false,
			args: args{
				url: "http://localhost" + portString + "/mtwilson/v2/reports",
			},
		},
	}
	for _, tt := range tests {

		_ = aas.NewJWTClient("")
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.c.GetSamlReports(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetSamlReports() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}