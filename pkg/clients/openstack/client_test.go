/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package openstack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/clients"
)

var authenticationResponseFilePath = "../../ihub/test/resources/auth_response.json"
var allTraitsFilePath = "../../ihub/test/resources/all_traits.json"
var openstackAuthToken = "gAAAAABfCJHzESrTqqH7H3Vpx7RWAdZehUb9gojm11klJ8RIXzhMEnkG94HLTFepQNrctmngE4qRmHolWNNyKO6UYjIKC8QmyGyUksLZxtcjMYlQbVfshCqwxW0iuVF_X9LnQIqbxucfqTjzf8nXVg2Yp3Onxves_ghQAUlld3-dMY-eFf8aDKc"
var userName = "admin"
var password = "password"
var traitsUrl *url.URL
var emptyUrl *url.URL

func TestNewOpenstackClient(t *testing.T) {
	httpServer, portString := mockOpenstackServer(t)
	defer func() {
		derr := httpServer.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()

	type args struct {
		authRL   string
		apiURL   string
		userName string
		password string
		certPath string
	}
	tests := []struct {
		name       string
		args       args
		wantClient bool
		wantErr    bool
		certPath   string
	}{
		{
			name: "Test For New client with Valid data",
			args: args{
				authRL:   "http://localhost" + portString + "/v3/auth/tokens",
				apiURL:   "http://localhost" + portString + "/",
				userName: userName,
				password: password,
			},
			wantClient: true,
			wantErr:    false,
		},
		{
			name: "Test For New client with Valid but incorrect password",
			args: args{
				authRL:   "http://localhost" + portString + "/v3/auth/tokens",
				apiURL:   "http://localhost" + portString + "/",
				userName: userName,
				password: "423",
			},
			wantClient: false,
			wantErr:    true,
		},
		{
			name: "Test For New client with Empty data",
			args: args{
				authRL:   "",
				apiURL:   "",
				userName: "admin1",
				password: "password",
			},
			wantClient: false,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authUrl, err := url.Parse(tt.args.authRL)
			if err != nil {
				t.Errorf("openstack/client_test:TestNewOpenstackClient(): unable to parse the auth url,error = %v", err)
				return
			}
			apiUrl, err := url.Parse(tt.args.apiURL)
			if err != nil {
				t.Errorf("openstack/client_test:TestNewOpenstackClient(): unable to parse the api url,error = %v", err)
				return
			}
			got, err := NewOpenstackClient(authUrl, apiUrl, tt.args.userName, tt.args.password, tt.args.certPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("openstack/client_test:TestNewOpenstackClient(): error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (got != nil) != tt.wantClient {
				t.Errorf("openstack/client_test:TestNewOpenstackClient(): recevived Client = %v, wanted Client %v", got, tt.wantClient)
			}

		})
	}
}

func TestSendRequest(t *testing.T) {
	h, portString := mockOpenstackServer(t)
	defer func() {
		derr := h.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()

	authUrl, err := url.Parse("http://localhost" + portString + "/v3/auth/tokens")
	if err != nil {
		t.Errorf("openstack/client_test:TestSendRequest(): unable to parse the auth url,error = %v", err)
		return
	}
	apiUrl, err := url.Parse("http://localhost" + portString + "/")
	if err != nil {
		t.Errorf("openstack/client_test:TestSendRequest(): unable to parse the api url,error = %v", err)
		return
	}
	traitsUrl, err = url.Parse("http://localhost" + portString + "/traits")
	if err != nil {
		t.Errorf("openstack/client_test:TestSendRequest(): unable to parse the traits url,error = %v", err)
		return
	}
	emptyUrl, err = url.Parse("")
	if err != nil {
		t.Errorf("openstack/client_test:TestSendRequest(): unable to parse the empty url,error = %v", err)
		return
	}

	errAuthUrl, err := url.Parse("http://localhost" + portString + "/v3/auth/tok")
	if err != nil {
		t.Errorf("openstack/client_test:TestSendRequest(): unable to parse the err auth url,error = %v", err)
		return
	}

	tests := []struct {
		name            string
		openStackClient Client
		reqParams       *RequestParams
		wantErr         bool
	}{
		{
			name: "Test For SendRequest with valid data",
			reqParams: &RequestParams{
				Method: "GET",
				URL:    traitsUrl,
				Body:   nil,
			},
			openStackClient: Client{
				AuthURL:  authUrl,
				ApiURL:   apiUrl,
				UserName: "admin",
				Password: "password",
			},
			wantErr: false,
		},
		{
			name: "Test For SendRequest with Invalid auth Url",
			reqParams: &RequestParams{
				Method: "GET",
				URL:    traitsUrl,
				Body:   nil,
			},
			openStackClient: Client{
				AuthURL:  errAuthUrl,
				ApiURL:   apiUrl,
				UserName: "admin",
				Password: "password",
			},
			wantErr: true,
		},
		{
			name: "Test For SendRequest with Invalid data",
			reqParams: &RequestParams{
				Method: "GET",
				URL:    traitsUrl,
				Body:   nil,
			},
			openStackClient: Client{
				AuthURL:  emptyUrl,
				ApiURL:   emptyUrl,
				UserName: "",
				Password: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tt.openStackClient.HTTPClient = clients.HTTPClientTLSNoVerify()

			_, err := tt.openStackClient.SendRequest(tt.reqParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("openstack/client_test:TestSendRequest(): error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestUpdateOpenstackToken(t *testing.T) {

	h, portString := mockOpenstackServer(t)
	defer func() {
		derr := h.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()

	authUrl, err := url.Parse("http://localhost" + portString + "/v3/auth/tokens")
	if err != nil {
		t.Errorf("openstack/client_test:TestUpdateOpenstackToken(): unable to parse the auth url,error = %v", err)
		return
	}
	apiUrl, err := url.Parse("http://localhost" + portString + "/")
	if err != nil {
		t.Errorf("openstack/client_test:TestUpdateOpenstackToken(): unable to parse the api url,error = %v", err)
		return
	}

	emptyUrl, err = url.Parse("")
	if err != nil {
		t.Errorf("openstack/client_test:TestUpdateOpenstackToken(): unable to parse the empty url,error = %v", err)
		return
	}

	tests := []struct {
		name    string
		o       *Client
		wantErr bool
	}{
		{
			name: "Test 1",
			o: &Client{
				ApiURL:     apiUrl,
				AuthURL:    authUrl,
				UserName:   "admin",
				Password:   "password",
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},

		{
			name: "Test 2",
			o: &Client{
				ApiURL:     emptyUrl,
				AuthURL:    emptyUrl,
				UserName:   "",
				Password:   "",
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},

		{
			name: "Test 3",
			o: &Client{
				ApiURL:     apiUrl,
				AuthURL:    authUrl,
				UserName:   "",
				Password:   "",
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.o.updateOpenstackToken(); (err != nil) != tt.wantErr {
				t.Errorf("openstack/client_test:TestUpdateOpenstackToken() : error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetOpenstackHTTPClient(t *testing.T) {

	h, portString := mockOpenstackServer(t)
	defer func() {
		derr := h.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing server")
		}
	}()

	authUrl, err := url.Parse("http://localhost" + portString + "/v3/auth/tokens")
	if err != nil {
		t.Errorf("openstack/client_test:TestUpdateOpenstackToken(): unable to parse the auth url,error = %v", err)
		return
	}

	apiUrl, err := url.Parse("http://localhost" + portString + "/")
	if err != nil {
		t.Errorf("openstack/client_test:TestUpdateOpenstackToken(): unable to parse the api url,error = %v", err)
		return
	}

	tests := []struct {
		name    string
		o       *Client
		wantErr bool
	}{
		{
			name: "Test 1",
			o: &Client{
				ApiURL:     apiUrl,
				AuthURL:    authUrl,
				UserName:   "admin",
				Password:   "password",
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Test 2",
			o: &Client{
				ApiURL:     apiUrl,
				AuthURL:    authUrl,
				UserName:   "admin",
				Password:   "password",
				HTTPClient: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.o.getOpenstackHTTPClient()
			if (err != nil) != tt.wantErr {
				t.Errorf("openstack/client_test:TestGetOpenstackHTTPClient() : error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func mockOpenstackServer(t *testing.T) (*http.Server, string) {
	r := mux.NewRouter()

	r.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		var auth Authorization
		json.NewDecoder(r.Body).Decode(&auth)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if userName == auth.Auth.Identity.Password.User.Name && password == auth.Auth.Identity.Password.User.Password {
			w.Header().Set("X-Subject-Token", openstackAuthToken)
			authenticationResponse, err := ioutil.ReadFile(authenticationResponseFilePath)
			if err != nil {
				t.Log("openstack/client_test:mockOpenstackServer() : Unable to read file", err)
			}
			w.Write([]byte(authenticationResponse))
			w.WriteHeader(201)
		} else {
			w.Header().Set("X-Subject-Token", "")
			w.Write([]byte(""))
			w.WriteHeader(401)
		}
	}).Methods("POST")

	r.HandleFunc("/traits", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if openstackAuthToken == r.Header.Get("x-auth-token") {
			allTraits, err := ioutil.ReadFile(allTraitsFilePath)
			if err != nil {
				t.Log("openstack/client_test:mockOpenstackServer() : Unable to read file", err)
			}
			w.Write([]byte(allTraits))
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}).Methods("GET")

	return serveController(t, r)

}

func serveController(t *testing.T, r http.Handler) (*http.Server, string) {

	//Listener Implementations
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Log("openstack/client_test:ServeController() : Unable to initiate Listener", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	err = listener.Close()
	if err != nil {
		t.Log("openstack/client_test:ServeController() : Unable to close Listener", err)
	}
	portString := fmt.Sprintf(":%d", port)

	h := &http.Server{
		Addr:    portString,
		Handler: r,
	}
	go h.ListenAndServe()

	return h, portString
}
