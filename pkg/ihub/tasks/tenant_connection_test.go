/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	testutility "github.com/intel-secl/intel-secl/v3/pkg/ihub/test"
	"github.com/spf13/viper"
)

func TestTenantConnectionRun(t *testing.T) {

	server, portString := testutility.MockServer(t)
	port := strings.Trim(portString, ":")
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	openstackConfig := testutility.SetupMockOpenStackConfiguration(t, portString)
	k8sConfig := testutility.SetupMockK8sConfiguration(t, portString)
	k8sConfig.Endpoint.CertFile = constants.DefaultK8SCertFile

	type args struct {
		EnvValues map[string]string
	}
	tests := []struct {
		name             string
		tenantConnection TenantConnection
		args             args
		wantErr          bool
	}{

		{
			name: "tenant-connection-kubernetes negative test 1",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       "",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 2",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       "https://localhost:" + port + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     "",
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 3",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       "https://localhost:" + port + "/",
					"KUBERNETES_CRD":       "",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": "",
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 4",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       "https://localhost:" + port + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 5",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"KUBERNETES_URL":       "https://localhost:" + port + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack valid test",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_API_PORT":  port,
					"OPENSTACK_USERNAME":  openstackConfig.Endpoint.UserName,
					"OPENSTACK_PASSWORD":  openstackConfig.Endpoint.Password,
				},
			},
			wantErr: false,
		},
		{
			name: "tenant-connection-openstack negative test 1",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_USERNAME":  openstackConfig.Endpoint.UserName,
					"OPENSTACK_PASSWORD":  openstackConfig.Endpoint.Password,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack negative test 2",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_USERNAME":  openstackConfig.Endpoint.UserName,
					"OPENSTACK_PASSWORD":  openstackConfig.Endpoint.Password,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack negative test 3",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_API_PORT":  port,
					"OPENSTACK_USERNAME":  openstackConfig.Endpoint.UserName,
					"OPENSTACK_PASSWORD":  openstackConfig.Endpoint.Password,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack negative test 4",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_API_PORT":  port,
					"OPENSTACK_PASSWORD":  openstackConfig.Endpoint.Password,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack negative test 5",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_API_PORT":  port,
					"OPENSTACK_USERNAME":  openstackConfig.Endpoint.UserName,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack negative test 6",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_API_PORT":  port,
					"OPENSTACK_USERNAME":  "",
					"OPENSTACK_PASSWORD":  openstackConfig.Endpoint.Password,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-openstack negative test 7",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{},
				ConsoleWriter:     os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":              openstackConfig.Endpoint.Type,
					"OPENSTACK_IP":        "localhost",
					"OPENSTACK_AUTH_PORT": port,
					"OPENSTACK_API_PORT":  port,
					"OPENSTACK_USERNAME":  openstackConfig.Endpoint.UserName,
					"OPENSTACK_PASSWORD":  "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			for key := range tt.args.EnvValues {
				os.Setenv(key, tt.args.EnvValues[key])
				defer os.Unsetenv(key)
			}
			temp, err := ioutil.TempFile("", "config.yml")
			if err != nil {
				t.Log("tasks/tenant_connection_test:TestTenantConnectionRun(): Error in Reading Config File")
			}
			defer func() {
				derr := os.Remove(temp.Name())
				if derr != nil {
					t.Errorf("Error removing file :%v", derr)
				}
			}()
			conf, _ := config.LoadConfiguration()
			tt.tenantConnection.TenantConfig = &conf.Endpoint

			err = tt.tenantConnection.Run()
			goterr := err != nil
			if goterr != tt.wantErr {
				t.Errorf("tasks/tenant_connection_test:TestTenantConnectionRun() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTenantConnectionValidate(t *testing.T) {

	server, portString := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	k8sConfig := testutility.SetupMockK8sConfiguration(t, portString)

	tests := []struct {
		name             string
		tenantConnection TenantConnection
		wantErr          bool
	}{
		{
			name: "tenant-connection-validate valid test",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{
					Type:     constants.OpenStackTenant,
					AuthURL:  "http://localhost" + portString + "/v3/auth/tokens",
					URL:      "http://localhost" + portString + "/",
					UserName: "admin",
					Password: "password",
				},
				ConsoleWriter:     os.Stdout,
			},
			wantErr: false,
		},
		{
			name: "tenant-connection-validate openstack negative test",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{
					Type:     constants.OpenStackTenant,
					AuthURL:  "",
					URL:      "",
					UserName: "admin",
					Password: "password",
				},
				ConsoleWriter:     os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-validate k8s negative test",
			tenantConnection: TenantConnection{
				TenantConfig: &config.Endpoint{
					Type:     k8sConfig.Endpoint.Type,
					URL:      "",
					CRDName:  "",
					Token:    "",
					CertFile: "",
				},
				ConsoleWriter:     os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if err := tt.tenantConnection.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("tasks/tenant_connection_test:TestTenantConnectionValidate(): error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTenantConnection_validateService(t *testing.T) {

	server, portString := testutility.MockServer(t)
	defer func() {
		derr := server.Close()
		if derr != nil {
			t.Errorf("Error closing mock server: %v",derr)
		}
	}()

	openstackConfig := testutility.SetupMockOpenStackConfiguration(t, portString)
	k8sConfig := testutility.SetupMockK8sConfiguration(t, portString)

	t1 := TenantConnection{
		TenantConfig: &openstackConfig.Endpoint,
		ConsoleWriter:     os.Stdout,
	}

	t2 := TenantConnection{
		TenantConfig: &k8sConfig.Endpoint,
		ConsoleWriter:     os.Stdout,
	}

	tests := []struct {
		name             string
		tenantConnection TenantConnection
		wantErr          bool
	}{
		{name: "tenant-connection-validate-service openstack valid test 1",
			tenantConnection: t1,
			wantErr:          false,
		},
		{
			name:             "tenant-connection-validate-service k8s valid test 2",
			tenantConnection: t2,
			wantErr:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.tenantConnection.validateService(); (err != nil) != tt.wantErr {
				t.Errorf("TenantConnection.validateService() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
