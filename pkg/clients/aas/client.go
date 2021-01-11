/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	types "github.com/intel-secl/intel-secl/v3/pkg/model/aas"
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
)

type Client struct {
	BaseURL    string
	JWTToken   []byte
	HTTPClient *http.Client
}

var (
	ErrHTTPCreateUser = &clients.HTTPClientErr{
		ErrMessage: "Failed to create user",
	}
	ErrHTTPCreateRole = &clients.HTTPClientErr{
		ErrMessage: "Failed to create role",
	}
	ErrHTTPAddRoleToUser = &clients.HTTPClientErr{
		ErrMessage: "Failed to add role to user",
	}
	ErrHTTPUpdateUser = &clients.HTTPClientErr{
		ErrMessage: "Failed to update user",
	}
	ErrHTTPGetUsers = &clients.HTTPClientErr{
		ErrMessage: "Failed to get user",
	}
	ErrHTTPGetRoles = &clients.HTTPClientErr{
		ErrMessage: "Failed to get roles",
	}
	ErrHTTPGetPermissionsForUser = &clients.HTTPClientErr{
		ErrMessage: "Failed to get permissions for user",
	}
	ErrHTTPGetRolesForUser = &clients.HTTPClientErr{
		ErrMessage: "Failed to get roles for user",
	}
)

func (c *Client) prepReqHeader(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+string(c.JWTToken))
}

func (c *Client) CreateUser(u types.UserCreate) (*types.UserCreateResponse, error) {

	userURL := clients.ResolvePath(c.BaseURL, "users")

	payload, err := json.Marshal(&u)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, userURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return nil, errors.New("aasClient.CreateUser: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusCreated {
		ErrHTTPCreateUser.RetCode = rsp.StatusCode
		return nil, ErrHTTPCreateUser
	}
	var userCreateResponse types.UserCreateResponse
	err = json.NewDecoder(rsp.Body).Decode(&userCreateResponse)
	if err != nil {
		return nil, err
	}
	return &userCreateResponse, nil
}

func (c *Client) GetUsers(name string) ([]types.UserCreateResponse, error) {

	relativeUrl := "users"
	u, _ := url.Parse(relativeUrl)
	queryString := u.Query()
	if name != "" {
		queryString.Set("name", name)
	}

	u.RawQuery = queryString.Encode()

	userURL := clients.ResolvePath(c.BaseURL, u.ResolveReference(u).String())

	req, err := http.NewRequest(http.MethodGet, userURL, nil)
	if err != nil {
		return nil, err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return nil, errors.New("aasClient.GetUsers: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPGetUsers.RetCode = rsp.StatusCode
		return nil, ErrHTTPGetUsers
	}
	var users []types.UserCreateResponse
	err = json.NewDecoder(rsp.Body).Decode(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (c *Client) CreateRole(r types.RoleCreate) (*types.RoleCreateResponse, error) {

	roleURL := clients.ResolvePath(c.BaseURL, "roles")

	payload, err := json.Marshal(&r)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, roleURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return nil, errors.New("aasClient.CreateRole: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	msg, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode != http.StatusCreated {
		ErrHTTPCreateRole.RetCode = rsp.StatusCode
		ErrHTTPCreateRole.RetMessage = string(msg)
		log.Errorf("Role not created. http errorcode : %d, message: %s", ErrHTTPCreateRole.RetCode, ErrHTTPCreateRole.RetMessage)
		return nil, ErrHTTPCreateRole
	}
	var roleCreateResponse types.RoleCreateResponse
	err = json.Unmarshal(msg, &roleCreateResponse)
	if err != nil {
		log.WithError(err).Error("CreateRole could not decode response")
		return nil, err
	}
	return &roleCreateResponse, nil
}

func (c *Client) GetRoles(service, name, context, contextContains string, allContexts bool) ([]types.RoleCreateResponse, error) {

	relativeUrl := "roles"
	u, _ := url.Parse(relativeUrl)
	queryString := u.Query()
	if service != "" {
		queryString.Set("service", service)
	}
	if name != "" {
		queryString.Set("name", name)
	}
	if context != "" {
		queryString.Set("context", context)
	}
	if contextContains != "" {
		queryString.Set("contextContains", contextContains)
	}
	if allContexts {
		queryString.Set("allContexts", "true")
	} else {
		queryString.Set("allContexts", "false")
	}

	u.RawQuery = queryString.Encode()

	rolesURL := clients.ResolvePath(c.BaseURL, u.ResolveReference(u).String())

	req, err := http.NewRequest(http.MethodGet, rolesURL, nil)
	if err != nil {
		return nil, err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return nil, errors.New("aasClient.GetRoles: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPGetRoles.RetCode = rsp.StatusCode
		return nil, ErrHTTPCreateUser
	}
	var roles []types.RoleCreateResponse
	err = json.NewDecoder(rsp.Body).Decode(&roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (c *Client) GetPermissionsForUser(userID string) ([]types.PermissionInfo, error) {

	userRoleURL := clients.ResolvePath(c.BaseURL, "users/"+userID+"/permissions")

	req, err := http.NewRequest(http.MethodGet, userRoleURL, nil)
	if err != nil {
		return nil, err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return nil, errors.New("aasClient.GetPermissionsForUser: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPGetPermissionsForUser.RetCode = rsp.StatusCode
		return nil, ErrHTTPGetPermissionsForUser
	}

	var permissions []types.PermissionInfo
	err = json.NewDecoder(rsp.Body).Decode(&permissions)
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

func (c *Client) GetRolesForUser(userID string) ([]types.RoleInfo, error) {

	userRoleURL := clients.ResolvePath(c.BaseURL, "users/"+userID+"/roles")

	req, err := http.NewRequest(http.MethodGet, userRoleURL, nil)
	if err != nil {
		return nil, err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return nil, errors.New("aasClient.GetRolesForUser: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPGetRolesForUser.RetCode = rsp.StatusCode
		return nil, ErrHTTPGetRolesForUser
	}

	var roles []types.RoleInfo
	err = json.NewDecoder(rsp.Body).Decode(&roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (c *Client) UpdateUser(userID string, user types.UserCreate) error {

	userRoleURL := clients.ResolvePath(c.BaseURL, "users/"+userID)

	payload, err := json.Marshal(&user)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPatch, userRoleURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return errors.New("aaClient.UpdateUser: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPUpdateUser.RetCode = rsp.StatusCode
		return ErrHTTPUpdateUser
	}
	return nil
}

func (c *Client) AddRoleToUser(userID string, r types.RoleIDs) error {

	userRoleURL := clients.ResolvePath(c.BaseURL, "users/"+userID+"/roles")

	payload, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, userRoleURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	c.prepReqHeader(req)

	if c.HTTPClient == nil {
		return errors.New("aaClient.AddRoleToUser: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusCreated {
		ErrHTTPAddRoleToUser.RetCode = rsp.StatusCode
		return ErrHTTPAddRoleToUser
	}
	return nil
}
