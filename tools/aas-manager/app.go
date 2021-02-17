/*
Copyright © 2020 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	claas "github.com/intel-secl/intel-secl/v3/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"io"
	"math/big"
	"os"
	"strings"
)

const (
	HELP_NOSETUP          = "Don't add users, roles and user-roles to the Authentication Service"
	HELP_ANSWERFILE       = `Answer file constaining user input`
	HELP_USE_JSON         = "Use Json file as input instead of parsing env file"
	HELP_IN_JSON_FILE     = "Input Json file name - identical to use_json flag but can specify a different file name "
	HELP_OUT_JSON_FILE    = "Output json file name - identical to output_json flag but can specify a different file name"
	HELP_OUTPUT_JSON      = "Boolean value to indicate if the users and roles should be written to a output file"
	HELP_GENPASSWORD      = "Generate passwords if not specified"
	HELP_REGEN_TOKEN_ONLY = "Generate token only"
	HELP_HELP             = "Show Usage - if specified, all other options will be ignored"

	PASSWORD_SIZE = 20
)

type UserAndRolesCreate struct {
	aas.UserCreate                    //embed
	PrintBearerToken bool             `json:"print_bearer_token"`
	Roles            []aas.RoleCreate `json:"roles"`
}

type AasUsersAndRolesSetup struct {
	AasApiUrl        string               `json:"aas_api_url"`
	AasAdminUserName string               `json:"aas_admin_username"`
	AasAdminPassword string               `json:"aas_admin_password"`
	UsersAndRoles    []UserAndRolesCreate `json:"users_and_roles"`
}

type App struct {
	AasAPIUrl        string
	AasAdminUserName string
	AasAdminPassword string

	HvsCN         string
	HvsSanList    string
	IhubCN        string
	IhubSanList   string
	WlsCN         string
	WlsSanList    string
	TaCN          string
	TaSanList     string
	KbsCN         string
	KbsSanList    string
	ScsCN         string
	ScsSanList    string
	ShvsCN        string
	ShvsSanList   string
	SqvsCN        string
	SqvsSanList   string
	SagentCN      string
	SagentSanList string
	SkcLibCN      string

	InstallAdminUserName    string
	InstallAdminPassword    string
	GlobalAdminUserName     string
	GlobalAdminPassword     string
	HvsServiceUserName      string
	HvsServiceUserPassword  string
	IhubServiceUserName     string
	IhubServiceUserPassword string
	WpmServiceUserName      string
	WpmServiceUserPassword  string
	WlsServiceUserName      string
	WlsServiceUserPassword  string
	WlaServiceUserName      string
	WlaServiceUserPassword  string
	ScsServiceUserName      string
	ScsServiceUserPassword  string
	ShvsServiceUserName     string
	ShvsServiceUserPassword string
	KbsServiceUsername      string
	KbsServiceUserPassword  string
	SKCLibUsername          string
	SKCLibUserPassword      string
	SKCLibRoleContext       string
	SGXAgentUsername        string
	SGXAgentUserPassword    string

	Components     map[string]bool
	GenPassword    bool
	RegenTokenOnly bool

	ConsoleWriter io.Writer
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
}

func RandomString(n int) string {
	var letter = []rune("~=+%^*/()[]{}/!@#$?|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	for i := range b {
		randRange, err := rand.Int(rand.Reader, big.NewInt(int64(len(letter))))
		if err != nil {
			log.WithError(err).Error("Error getting a random index for a character to create random string")
			return ""
		}
		b[i] = letter[randRange.Int64()]
	}
	return string(b)
}

func MakeTlsCertificateRole(cn, san string) aas.RoleCreate {
	r := aas.RoleCreate{}
	r.Service = "CMS"
	r.Name = "CertApprover"
	r.Context = "CN=" + cn + ";SAN=" + san + ";certType=TLS"
	return r
}

func MakeTlsClientCertificateRole(cn string) aas.RoleCreate {
	r := aas.RoleCreate{}
	r.Service = "CMS"
	r.Name = "CertApprover"
	r.Context = "CN=" + cn + ";certType=TLS-Client"
	return r
}

func NewRole(service, name, context string, perms []string) aas.RoleCreate {
	r := aas.RoleCreate{}
	r.Service = service
	r.Name = name
	r.Context = context
	if len(perms) > 0 {
		r.Permissions = append([]string(nil), perms...)
	}
	return r
}

func (a *App) GetServiceUsers() []UserAndRolesCreate {

	urs := []UserAndRolesCreate{}
	for k := range a.Components {

		urc := UserAndRolesCreate{}
		urc.Roles = []aas.RoleCreate{}

		switch k {
		case "HVS":
			urc.Name = a.HvsServiceUserName
			urc.Password = a.HvsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("TA", "Administrator", "", []string{"*:*:*"}))
		case "IHUB":
			urc.Name = a.IhubServiceUserName
			urc.Password = a.IhubServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("HVS", "ReportSearcher", "", []string{"reports:search:*"}))
		case "WPM":
			urc.Name = a.WpmServiceUserName
			urc.Password = a.WpmServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("KBS", "KeyManager", "", []string{"keys:create:*", "keys:transfer:*"}))
		case "WLS":
			urc.Name = a.WlsServiceUserName
			urc.Password = a.WlsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("HVS", "ReportCreator", "", []string{"reports:create:*"}))
		case "WLA":
			urc.Name = a.WlaServiceUserName
			urc.Password = a.WlaServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("WLS", "FlavorsImageRetrieval", "", []string{"image_flavors:retrieve:*"}))
			urc.Roles = append(urc.Roles, NewRole("WLS", "ReportCreator", "", []string{"reports:create:*"}))
			urc.Roles = append(urc.Roles, NewRole("WLS", "KeysCreator", "", []string{"keys:create:*"}))
		case "SCS":
			urc.Name = a.ScsServiceUserName
			urc.Password = a.ScsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("SCS", "CacheManager", "", nil))
		case "SHVS":
			urc.Name = a.ShvsServiceUserName
			urc.Password = a.ShvsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("SHVS", "HostsListReader", "", nil))
			urc.Roles = append(urc.Roles, NewRole("SHVS", "HostListManager", "", nil))
		case "SIH":
			urc.Name = a.IhubServiceUserName
			urc.Password = a.IhubServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("SHVS", "HostDataReader", "", nil))
		case "SKBS":
			urc.Name = a.KbsServiceUsername
			urc.Password = a.KbsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("SQVS", "QuoteVerifier", "", nil))
			urc.Roles = append(urc.Roles, NewRole("AAS", "Administrator", "", []string{"*:*:*"}))
		case "SKC-LIBRARY":
			urc.Name = a.SKCLibUsername
			urc.Password = a.SKCLibUserPassword
			urc.Roles = append(urc.Roles, NewRole("KBS", "KeyTransfer", a.SKCLibRoleContext, nil))
		case "SGX_AGENT":
			urc.Name = a.SGXAgentUsername
			urc.Password = a.SGXAgentUserPassword
			urc.Roles = append(urc.Roles, NewRole("SHVS", "HostDataUpdater", "", nil))
			urc.Roles = append(urc.Roles, NewRole("SCS", "HostDataUpdater", "", nil))
			urc.Roles = append(urc.Roles, NewRole("SCS", "HostDataReader", "", nil))
		}
		if urc.Name != "" {
			urs = append(urs, urc)
		}

	}
	return urs

}

func (a *App) GetGlobalAdminUser() *UserAndRolesCreate {

	if a.GlobalAdminUserName == "" {
		return nil
	}

	urc := UserAndRolesCreate{}
	urc.Name = a.GlobalAdminUserName
	urc.Password = a.GlobalAdminPassword
	urc.Roles = []aas.RoleCreate{}

	for k := range a.Components {

		switch k {
		case "HVS":
			urc.Roles = append(urc.Roles, NewRole("HVS", "Administrator", "", []string{"*:*:*"}))
		case "TA":
			urc.Roles = append(urc.Roles, NewRole("TA", "Administrator", "", []string{"*:*:*"}))
		case "KBS":
			urc.Roles = append(urc.Roles, NewRole("KBS", "Administrator", "", []string{"*:*:*"}))
		case "WLS":
			urc.Roles = append(urc.Roles, NewRole("WLS", "Administrator", "", []string{"*:*:*"}))
		case "AAS":
			urc.Roles = append(urc.Roles, NewRole("AAS", "Administrator", "", []string{"*:*:*"}))
		}
	}
	return &urc
}

func (a *App) GetSuperInstallUser() UserAndRolesCreate {

	// set the user
	urc := UserAndRolesCreate{}
	urc.Name = a.InstallAdminUserName
	urc.Password = a.InstallAdminPassword
	urc.PrintBearerToken = true
	urc.Roles = []aas.RoleCreate{}

	// set the roles depending on the components that are to be installed

	for k := range a.Components {
		switch k {
		case "HVS":
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=HVS Flavor Signing Certificate;certType=Signing", nil))
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.HvsCN, a.HvsSanList))
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=HVS SAML Certificate;certType=Signing", nil))
		case "TA":
			urc.Roles = append(urc.Roles, NewRole("HVS", "AttestationRegister", "",
				[]string{"host_tls_policies:create:*", "hosts:create:*", "hosts:store:*", "hosts:search:*",
					"host_unique_flavors:create:*", "flavors:search:*", "tpm_passwords:retrieve:*",
					"tpm_passwords:create:*", "host_aiks:certify:*", "tpm_endorsements:create:*", "tpm_endorsements:search:*"}))
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.TaCN, a.TaSanList))
		case "IHUB", "SIH":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.IhubCN, a.IhubSanList))
		case "KBS", "SKBS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.KbsCN, a.KbsSanList))
		case "WPM":
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=WPM Flavor Signing Certificate;certType=Signing", nil))
		case "WLS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.WlsCN, a.WlsSanList))
		case "WLA":
			urc.Roles = append(urc.Roles, NewRole("HVS", "Certifier", "", []string{"host_signing_key_certificates:create:*"}))
		case "SCS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.ScsCN, a.ScsSanList))
		case "SQVS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.SqvsCN, a.SqvsSanList))
		case "SHVS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.ShvsCN, a.ShvsSanList))
		case "SKC-LIBRARY":
			urc.Roles = append(urc.Roles, MakeTlsClientCertificateRole(a.SkcLibCN))

		}
	}

	return urc

}

func SetVariable(variable *string, envVarName string, defaultVal string, desc string, mandatory bool, secret bool) error {
	if *variable = os.Getenv(envVarName); *variable == "" {
		if mandatory {
			fmt.Println(envVarName, "-", desc, " is mandatory and cannot be empty")
			return fmt.Errorf("required environment variable missing")
		}

	}
	if *variable == "" && defaultVal != "" {
		*variable = defaultVal
	}

	if secret {
		fmt.Println(desc, "= *******")
	} else {
		fmt.Println(desc, "=", *variable)
	}

	return nil
}

func (a *App) LoadAllVariables(envFile string) error {
	if err := godotenv.Load(envFile); err != nil {
		fmt.Println("could not load environment file :", envFile, ". Will be using existing exported environment variables")
	}

	// mandatory variables

	var installComps string

	type envDesc struct {
		variable    *string
		envVarName  string
		defaultVal  string
		description string
		mandatory   bool
		secret      bool
	}

	envVars := []envDesc{
		{&a.AasAPIUrl, "AAS_API_URL", "", "AAS API URL", true, false},
		{&a.AasAdminUserName, "AAS_ADMIN_USERNAME", "", "AAS ADMIN USERNAME", true, false},
		{&a.AasAdminPassword, "AAS_ADMIN_PASSWORD", "", "AAS ADMIN PASSWORD", true, true},

		{&installComps, "ISECL_INSTALL_COMPONENTS", "", "ISecl Components to be installed", true, true},

		{&a.InstallAdminUserName, "INSTALL_ADMIN_USERNAME", "installadmin", "Installation ADMIN USERNAME", false, false},
		{&a.InstallAdminPassword, "INSTALL_ADMIN_PASSWORD", "", "Installation ADMIN PASSWORD", false, true},

		{&a.HvsCN, "HVS_CERT_COMMON_NAME", "HVS TLS Certificate", "Host Verification Service TLS Certificate Common Name", false, false},
		{&a.HvsSanList, "HVS_CERT_SAN_LIST", "", "Host Verification Service TLS Certificate SAN LIST", false, false},

		{&a.IhubCN, "IH_CERT_COMMON_NAME", "Integration Hub TLS Certificate", "Integration Hub TLS Certificate Common Name", false, false},
		{&a.IhubSanList, "IH_CERT_SAN_LIST", "", "Integration Hub TLS Certificate SAN LIST", false, false},

		{&a.WlsCN, "WLS_CERT_COMMON_NAME", "WLS TLS Certificate", "Workload Service TLS Certificate Common Name", false, false},
		{&a.WlsSanList, "WLS_CERT_SAN_LIST", "", "Workload Service TLS Certificate SAN LIST", false, false},

		{&a.KbsCN, "KBS_CERT_COMMON_NAME", "KBS TLS Certificate", "Key Broker Service TLS Certificate Common Name", false, false},
		{&a.KbsSanList, "KBS_CERT_SAN_LIST", "", "Key Broker Service TLS Certificate SAN LIST", false, false},

		{&a.TaCN, "TA_CERT_COMMON_NAME", "Trust Agent TLS Certificate", "Trust Agent TLS Certificate Common Name", false, false},
		{&a.TaSanList, "TA_CERT_SAN_LIST", "", "Trust Agent TLS Certificate SAN LIST", false, false},

		{&a.ScsCN, "SCS_CERT_COMMON_NAME", "SCS TLS Certificate", "SGX Caching Service TLS Certificate Common Name", false, false},
		{&a.ScsSanList, "SCS_CERT_SAN_LIST", "", "SGX Caching Service TLS Certificate SAN LIST", false, false},

		{&a.SqvsCN, "SQVS_CERT_COMMON_NAME", "SQVS TLS Certificate", "SGX Quote Verification Service TLS Certificate Common Name", false, false},
		{&a.SqvsSanList, "SQVS_CERT_SAN_LIST", "", "SGX Quote Verification Service TLS Certificate SAN LIST", false, false},

		{&a.ShvsCN, "SHVS_CERT_COMMON_NAME", "SHVS TLS Certificate", "SGX Host Verification Service TLS Certificate Common Name", false, false},
		{&a.ShvsSanList, "SHVS_CERT_SAN_LIST", "", "SGX Host Verification Service TLS Certificate SAN LIST", false, false},

		{&a.SagentCN, "SGX_AGENT_CERT_COMMON_NAME", "SGX_AGENT TLS Certificate", "SGX Agent TLS Certificate Common Name", false, false},
		{&a.SagentSanList, "SGX_AGENT_CERT_SAN_LIST", "", "SGX Agent TLS Certificate SAN LIST", false, false},

		{&a.SkcLibCN, "SKC_LIBRARY_CERT_COMMON_NAME", "skcuser", "SKC Library TLS Client Certificate Common Name", false, false},

		{&a.GlobalAdminUserName, "GLOBAL_ADMIN_USERNAME", "", "Global Admin User Name", false, false},
		{&a.GlobalAdminPassword, "GLOBAL_ADMIN_PASSWORD", "", "Global Admin User Password", false, true},

		{&a.HvsServiceUserName, "HVS_SERVICE_USERNAME", "", "Host Verification Service User Name", false, false},
		{&a.HvsServiceUserPassword, "HVS_SERVICE_PASSWORD", "", "Host Verification Service User Password", false, true},

		{&a.IhubServiceUserName, "IHUB_SERVICE_USERNAME", "", "Integration Hub Service User Name", false, false},
		{&a.IhubServiceUserPassword, "IHUB_SERVICE_PASSWORD", "", "Integration Hub Service User Password", false, true},

		{&a.WpmServiceUserName, "WPM_SERVICE_USERNAME", "", "Workload Policy Manager Service User Name", false, false},
		{&a.WpmServiceUserPassword, "WPM_SERVICE_PASSWORD", "", "Workload Policy Manager Service User Password", false, true},

		{&a.WlsServiceUserName, "WLS_SERVICE_USERNAME", "", "Workload Service User Name", false, false},
		{&a.WlsServiceUserPassword, "WLS_SERVICE_PASSWORD", "", "Workload Service User Password", false, true},

		{&a.WlaServiceUserName, "WLA_SERVICE_USERNAME", "", "Workload Agent User Name", false, false},
		{&a.WlaServiceUserPassword, "WLA_SERVICE_PASSWORD", "", "Workload Agent User Password", false, true},

		{&a.ScsServiceUserName, "SCS_SERVICE_USERNAME", "", "SGX Caching Service User Name", false, false},
		{&a.ScsServiceUserPassword, "SCS_SERVICE_PASSWORD", "", "SGX Caching Service User Password", false, true},

		{&a.ShvsServiceUserName, "SHVS_SERVICE_USERNAME", "", "SGX Host Verification Service User Name", false, false},
		{&a.ShvsServiceUserPassword, "SHVS_SERVICE_PASSWORD", "", "SGX Host Verification Service User Password", false, true},

		{&a.KbsServiceUsername, "KBS_SERVICE_USERNAME", "", "Key Broker Service User Name", false, false},
		{&a.KbsServiceUserPassword, "KBS_SERVICE_PASSWORD", "", "Key Broker Service User Password", false, true},

		{&a.SKCLibUsername, "SKC_LIBRARY_USERNAME", "", "SKC Library User Name", false, false},
		{&a.SKCLibUserPassword, "SKC_LIBRARY_PASSWORD", "", "SKC Library User Password", false, true},

		{&a.SKCLibRoleContext, "SKC_LIBRARY_KEY_TRANSFER_CONTEXT", "", "SKC Library Key Transfer Role Context", false, false},

		{&a.SGXAgentUsername, "SGX_AGENT_USERNAME", "", "SGX Agent User Name", false, false},
		{&a.SGXAgentUserPassword, "SGX_AGENT_PASSWORD", "", "SGX Agent User Password", false, true},
	}

	hasError := false

	for _, envVar := range envVars {
		if err := SetVariable(envVar.variable, envVar.envVarName, envVar.defaultVal, envVar.description, envVar.mandatory, envVar.secret); err != nil {
			hasError = true
		}
	}
	if hasError {
		return fmt.Errorf("Missing Required Environment variable(s). Set these in the env file or export them and run again")
	}

	// set up the app map with components that need to be installed
	slc := strings.Split(installComps, ",")
	a.Components = make(map[string]bool)
	for i := range slc {
		a.Components[strings.TrimSpace(slc[i])] = true
	}

	return nil

}

func (a *App) LoadUserAndRolesJson(file string) (*AasUsersAndRolesSetup, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read user role files %s : ", file)
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var urc AasUsersAndRolesSetup
	if err := dec.Decode(&urc); err != nil {
		return nil, fmt.Errorf("could not decode json file for user roles - %v", err)
	}
	return &urc, nil
}

func (a *App) GetNewOrExistingUserID(name, password string, forceUpdatePassword bool, aascl *claas.Client) (string, error) {

	users, err := aascl.GetUsers(name)
	if err != nil {
		return "", err
	}

	if len(users) == 0 {
		// did not find the user.. so let us create the user.

		// first check if the password is blank. If it is and we have to create a password
		if password == "" {
			return "", fmt.Errorf("Password not supplied and no flag to generate password. Use --genpassword flag to generate password")
		}
		newUser, err := aascl.CreateUser(aas.UserCreate{name, password})
		if err != nil {
			return "", err
		}
		return newUser.ID, nil
	}
	if len(users) == 1 && users[0].Name == name {
		// found single record that corresponds to the user.

		// if password is empty and we have to generate password, generate password and set it
		if forceUpdatePassword {
			if err := aascl.UpdateUser(users[0].ID, aas.UserCreate{name, password}); err != nil {
				return "", fmt.Errorf("Could not update the user : %s's password", name)
			}
		}
		return users[0].ID, nil
	}
	// we should not really be here.. we have multiple users with matched name
	return "", fmt.Errorf("Multiple records found when searching for user %s - record - %v", name, users)
}

func (a *App) GetNewOrExistingRoleID(role aas.RoleCreate, aascl *claas.Client) (string, error) {
	roles, err := aascl.GetRoles(role.Service, role.Name, role.Context, "", false)
	if err != nil {
		return "", err
	}

	if len(roles) == 0 {
		// did not find the role.. so create the role
		newRole, err := aascl.CreateRole(role)
		if err != nil {
			return "", err
		}
		return newRole.ID, nil
	}
	if len(roles) != 1 {
		// we should not really be here.. we have multiple roles with matched name
		return "", fmt.Errorf("Multiple records found when searching for role %v - record - %v", role, roles)
	}

	// found single record that corresponds to the user.
	return roles[0].ID, nil

}

func (a *App) GetUserToken(apiUrl, apiUserName, apiUserPass string) ([]byte, error) {
	// first create a JWT token for the admin
	jwtcl := claas.NewJWTClient(apiUrl)
	jwtcl.HTTPClient = clients.HTTPClientTLSNoVerify()

	jwtcl.AddUser(apiUserName, apiUserPass)
	err := jwtcl.FetchAllTokens()
	if err != nil {
		return nil, fmt.Errorf("Could not Fetch Token for for user: %s - error: %v", apiUserName, err)
	}

	token, err := jwtcl.GetUserToken(apiUserName)
	if err != nil {
		return nil, fmt.Errorf("Could not obtain token for %s from %s - err - %s", apiUserName, apiUrl, err)

	}

	return token, nil
}

func (a *App) PrintUserTokens(asr *AasUsersAndRolesSetup) error {

	for _, user := range asr.UsersAndRoles {
		if !user.PrintBearerToken {
			continue
		}
		token, err := a.GetUserToken(asr.AasApiUrl, user.Name, user.Password)
		if err != nil {
			return err
		}
		fmt.Println("\nToken for User:", user.Name)
		fmt.Printf("BEARER_TOKEN=%s\n", string(token))
		fmt.Println()
	}
	return nil

}

func (a *App) AddUsersAndRoles(asr *AasUsersAndRolesSetup) error {

	// no create an aas client with the token.

	token, err := a.GetUserToken(asr.AasApiUrl, asr.AasAdminUserName, asr.AasAdminPassword)
	if err != nil {
		return err
	}
	aascl := &claas.Client{asr.AasApiUrl, token, clients.HTTPClientTLSNoVerify()}

	//fmt.Println("BEARER_TOKEN="+string(token))
	for idx := range asr.UsersAndRoles {
		userid := ""
		if a.RegenTokenOnly && !asr.UsersAndRoles[idx].PrintBearerToken {
			continue
		}

		forcePasswordUpdate := false
		if asr.UsersAndRoles[idx].Password == "" && (a.GenPassword || asr.UsersAndRoles[idx].PrintBearerToken) {
			asr.UsersAndRoles[idx].Password = RandomString(PASSWORD_SIZE)
			forcePasswordUpdate = true
		}
		if userid, err = a.GetNewOrExistingUserID(asr.UsersAndRoles[idx].Name, asr.UsersAndRoles[idx].Password, forcePasswordUpdate, aascl); err == nil {
			fmt.Println("\nuser:", asr.UsersAndRoles[idx].Name, "userid:", userid)
		} else {
			return fmt.Errorf("Error while attempting to create/ retrieve user %s - error %v ", asr.UsersAndRoles[idx].Name, err)

		}
		if a.RegenTokenOnly {
			continue
		}
		// we might have the same role appear more than one in the list of roles to be added for a user
		// since different components might need the same roles. The Add user to role function relies on
		// having a unique list of roles. put the roleids into a map and then make a list.

		fmt.Println("\nGetting Roles for user")
		roleMap := make(map[string]bool)
		for _, role := range asr.UsersAndRoles[idx].Roles {
			if roleid, err := a.GetNewOrExistingRoleID(role, aascl); err == nil {
				fmt.Println("role:", role, "roleid:", roleid)
				roleMap[roleid] = true
			} else {
				return fmt.Errorf("Error while attempting to create/ retrieve role %s - error %v ", role.Name, err)
			}

		}
		roleList := []string{}
		for key := range roleMap {
			roleList = append(roleList, key)
		}

		fmt.Println("\nAdding Roles to user RolesIDs :", roleList)
		if err = aascl.AddRoleToUser(userid, aas.RoleIDs{roleList}); err != nil {
			return fmt.Errorf("Could not add roles to user - %s", asr.UsersAndRoles[idx].Name)
		}

	}
	return nil

}

func (a *App) Setup(args []string) error {
	var err error
	setup := true
	var noSetup, useJson, outputJson, printHelp bool
	var envFile, jsonIn, jsonOut string

	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.BoolVar(&noSetup, "nosetup", false, HELP_NOSETUP)
	fs.StringVar(&envFile, "answerfile", "populate-users.env", HELP_ANSWERFILE)
	fs.BoolVar(&useJson, "use_json", false, HELP_USE_JSON)
	fs.StringVar(&jsonIn, "in_json_file", "", HELP_IN_JSON_FILE)
	fs.StringVar(&jsonOut, "out_json_file", "", HELP_OUT_JSON_FILE)
	fs.BoolVar(&outputJson, "output_json", false, HELP_OUTPUT_JSON)
	fs.BoolVar(&a.GenPassword, "genpassword", false, HELP_GENPASSWORD)
	fs.BoolVar(&a.RegenTokenOnly, "regen_token_only", false, HELP_REGEN_TOKEN_ONLY)
	fs.BoolVar(&printHelp, "help", false, HELP_HELP)

	err = fs.Parse(args[1:])
	if err != nil {
		// return err
		return fmt.Errorf("could not parse the command line flags")
	}

	if printHelp || (len(args) == 2 && args[1] == "help") {
		fmt.Println("Usage:\n\n ", args[0], "[--answerfile] [--nosetup] [--genpassword] [--use_json] [--in_json_file] [--output_json] [--out_json_file] [--help]")

		fs.PrintDefaults()
		return nil
	}

	var as *AasUsersAndRolesSetup

	if useJson || jsonIn != "" {
		// do what is needed to parse the JSON file to create user and roles
		if jsonIn == "" {
			jsonIn = "./populate-users.json"
		}
		if as, err = a.LoadUserAndRolesJson(jsonIn); err != nil {
			fmt.Println(err)
			return err
		}

	} else {
		// call the method to load all the environment variable values
		fmt.Println("\n\nLoading environment variables\n=============================")

		if err := a.LoadAllVariables(envFile); err != nil {
			return fmt.Errorf("Could not find necessary environment variables - error %v ", err)
		}
		as = &AasUsersAndRolesSetup{AasApiUrl: a.AasAPIUrl, AasAdminUserName: a.AasAdminUserName, AasAdminPassword: a.AasAdminPassword}
		as.UsersAndRoles = append(as.UsersAndRoles, a.GetSuperInstallUser())
		as.UsersAndRoles = append(as.UsersAndRoles, a.GetServiceUsers()...)
		if glAdmin := a.GetGlobalAdminUser(); glAdmin != nil {
			as.UsersAndRoles = append(as.UsersAndRoles, *glAdmin)
		}

	}

	if noSetup {
		setup = false
	}

	if setup {
		if !a.RegenTokenOnly {
			fmt.Println("\n\nAdding Users and Roles\n======================")
		}
		if err = a.AddUsersAndRoles(as); err != nil {
			return err
		}
		fmt.Println("\n\nPrinting Tokens for specific users\n==================================")
		if err = a.PrintUserTokens(as); err != nil {
			return err
		}

	}

	if outputJson || jsonOut != "" {
		if jsonOut == "" {
			jsonOut = "./populate-users.json"
		}
		fmt.Println("\n\nWrting Output to json file - ", jsonOut)
		outFile, err := os.OpenFile(jsonOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
		if err != nil {
			fmt.Println("could not open output json file - %s for writing" + jsonOut)
		}
		defer func() {
			derr := outFile.Close()
			if derr != nil {
				fmt.Println("Error closing file" + derr.Error())
			}
		}()
		enc := json.NewEncoder(outFile)
		enc.SetIndent("", "    ")
		err = enc.Encode(as)
		if err != nil {
			err = fmt.Errorf("could not encode data - %s", err.Error())
			if err != nil {
				fmt.Println("\n Error printing errors")
			}
		}
	}
	return nil

}
func (a *App) Run(args []string) error {

	if err := a.Setup(args); err != nil {
		fmt.Println("Exit with Error!! - Setup not completed successfully. error -", err)
		return err
	}

	return nil
}
