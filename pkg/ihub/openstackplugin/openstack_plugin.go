/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package openstackplugin

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"net/url"

	"github.com/google/uuid"
	openstackClient "github.com/intel-secl/intel-secl/v3/pkg/clients/openstack"
	vsPlugin "github.com/intel-secl/intel-secl/v3/pkg/ihub/attestationPlugin"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	commonLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/openstack"
	"github.com/pkg/errors"
)

//HostDetails for Openstack
type HostDetails struct {
	hostName                   string
	hostIP                     string
	hostID                     uuid.UUID
	DefaultTraits              []string
	CustomTraits               []string
	ValidTo                    time.Time
	trusted                    bool
	ResourceProviderGeneration int
}

//OpenstackDetails for requesting auth and getting host list and updating traits
type OpenstackDetails struct {
	Config          *config.Configuration
	HostDetails     []HostDetails
	AllCustomTraits []string
	OpenstackClient *openstackClient.Client
}

var log = commonLog.GetDefaultLogger()

//GetHostsFromOpenstack Get Hosts from Openstack
func GetHostsFromOpenstack(openstackDetails *OpenstackDetails) error {
	log.Trace("openstackplugin/openstack_plugin:GetHostsFromOpenstack() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:GetHostsFromOpenstack() Leaving")

	prefixURL := openstackDetails.Config.Endpoint.URL
	resourcePath := "resource_providers"

	parsedUrl, err := url.Parse(prefixURL + resourcePath)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:GetHostsFromOpenstack()  Unable to parse the resource path url")
	}

	log.Debug("openstackplugin/openstack_plugin:GetHostsFromOpenstack() Sending request to Openstack client to get hosts")
	res, err := openstackDetails.OpenstackClient.SendRequest(&openstackClient.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:GetHostsFromOpenstack()  Error in getting the list of hosts from Openstack")
	}
	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:GetHostsFromOpenstack()  Error in reading the host details body")
	}

	var openStackResources model.OpenstackResources

	log.Debug("openstackplugin/openstack_plugin:GetHostsFromOpenstack() Unmarshalling the Openstack resources")
	err = json.Unmarshal(body, &openStackResources)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:GetHostsFromOpenstack()  Error in unmarshalling the host details from Openstack")
	}

	var hostDetailsList []HostDetails

	log.Debug("openstackplugin/openstack_plugin:GetHostsFromOpenstack() getting host details list from resource providers")
	for _, actualObject := range openStackResources.ResourceProviders {

		hostDetails := HostDetails{}
		hostDetails.hostID = actualObject.HostID
		hostDetails.hostName = actualObject.Name

		hostDetailsList = append(hostDetailsList, hostDetails)
		log.Debug("openstackplugin/openstack_plugin:GetHostsFromOpenstack() Host ID : ", actualObject.HostID)

	}
	openstackDetails.HostDetails = hostDetailsList
	log.Info("openstackplugin/openstack_plugin:GetHostsFromOpenstack() Retrieved the host details from Openstack")
	return nil
}

//FilterHostReportsForOpenstack Get Host Reports
func FilterHostReportsForOpenstack(hostDetails *HostDetails, openstackDetails *OpenstackDetails) error {

	log.Trace("openstackplugin/openstack_plugin:FilterHostReportsForOpenstack() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:FilterHostReportsForOpenstack() Leaving")

	log.Info("openstackplugin/openstack_plugin:FilterHostReportsForOpenstack() Get the host reports for Openstack")
	samlReport, err := vsPlugin.GetHostReports(hostDetails.hostName, openstackDetails.Config, constants.TrustedCAsStoreDir, constants.SamlCertFilePath)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:FilterHostReportsForOpenstack() : Error in getting the host report")

	}
	log.Info("openstackplugin/openstack_plugin:FilterHostReportsForOpenstack() Get the custom traits from report for Openstack")
	err = getCustomTraitsFromReport(hostDetails, samlReport)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:FilterHostReportsForOpenstack() : Error in generating custom traits from trust report")
	}

	return nil
}

func getCustomTraitsFromReport(hostDetails *HostDetails, samlReport *saml.Saml) error {

	log.Trace("openstackplugin/openstack_plugin:getCustomTraitsFromReport() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:getCustomTraitsFromReport() Leaving")

	var customTraits []string
	trusted := false

	log.Debug("openstackplugin/openstack_plugin:getCustomTraitsFromReport() Getting traits from the report")
	for _, as := range samlReport.Attribute {

		key := as.Name
		value := as.AttributeValue
		//Asset Tags
		if strings.HasPrefix(key, "TAG") {
			log.Debugf("openstackplugin/openstack_plugin:getCustomTraitsFromReport() Constructing custom trait for Asset tag: %s - %s", key, value)
			prefix := constants.TraitPrefix + constants.TraitAssetTagPrefix
			trait := GetFormattedCustomTraits(prefix, key, value)
			customTraits = append(customTraits, trait)

		}
		//Trust tags
		if strings.EqualFold(as.Name, "TRUST_OVERALL") && strings.EqualFold(value, "true") {
			log.Debug("openstackplugin/openstack_plugin:getCustomTraitsFromReport() Constructing custom trait for trust tag")
			customTraits = append(customTraits, constants.TrustedTrait)
			trusted = true
		}

		//HWFeature tags
		if strings.HasPrefix(as.Name, "FEATURE") && !strings.EqualFold(value, "false") {
			log.Debugf("openstackplugin/openstack_plugin:getCustomTraitsFromReport() Constructing custom trait for HWFeature tag: %s", key)
			prefix := constants.TraitPrefix + constants.TraitHardwareFeaturesPrefix
			trait := GetFormattedCustomTraits(prefix, key, "")
			customTraits = append(customTraits, trait)
		}

	}

	if trusted {
		hostDetails.CustomTraits = customTraits
		log.Debugf("Traits for host with name %s: %v", hostDetails.hostName, customTraits)
	} else {
		log.Warnf("Host with name %s is not trusted, removing all existing custom tags", hostDetails.hostName)
	}

	hostDetails.trusted = trusted
	return nil
}

//GetFormattedCustomTraits Format the custom Traits with the "CUSTOM_ISECL" prefix
func GetFormattedCustomTraits(prefix string, tagKey string, tagValue string) string {

	log.Trace("openstackplugin/openstack_plugin:GetFormattedCustomTraits() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:GetFormattedCustomTraits() Leaving")

	log.Debug("openstackplugin/openstack_plugin:GetFormattedCustomTraits() getting the formatted custom traits")
	delimiter := constants.TraitDelimiter

	key := strings.ReplaceAll(tagKey, delimiter, delimiter+delimiter)
	value := strings.ReplaceAll(tagValue, delimiter, delimiter+delimiter)

	rgx := regexp.MustCompile(constants.RegexNonStandardChar)

	newTagKey := rgx.ReplaceAllString(key, delimiter)
	newTagValue := rgx.ReplaceAllString(value, delimiter)

	log.Debug("openstackplugin/openstack_plugin:GetFormattedCustomTraits() Add the CUSTOM_ISECL prefix to formatted string")
	formattedString := prefix + strings.ToUpper(newTagKey)

	if newTagValue != "" {
		formattedString = formattedString + delimiter + strings.ToUpper(newTagValue)
	}

	log.Info("openstackplugin/openstack_plugin:GetFormattedCustomTraits() Custom traits are formatted")
	return formattedString
}

//UpdateOpenstackTraits Update the traits for the resources
func UpdateOpenstackTraits(openstackDetails *OpenstackDetails) error {

	log.Trace("openstackplugin/openstack_plugin:UpdateOpenstackTraits() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:UpdateOpenstackTraits() Leaving")

	for index := range openstackDetails.HostDetails {

		log.Debug("openstackplugin/openstack_plugin:UpdateOpenstackTraits() fetching all the traits for the resource")
		err := getTraitsForResource(&openstackDetails.HostDetails[index], openstackDetails)
		if err != nil {
			return errors.Wrap(err, "openstackplugin/openstack_plugin:UpdateOpenstackTraits() Error in getting Traits for the resource")
		}

		if len(openstackDetails.HostDetails[index].CustomTraits) > 0 {

			log.Debug("openstackplugin/openstack_plugin:UpdateOpenstackTraits() creating custom traits")
			err := createCustomTraits(openstackDetails.HostDetails[index].CustomTraits, openstackDetails)
			if err != nil {
				return errors.Wrap(err, "openstackplugin/openstack_plugin:UpdateOpenstackTraits() Error in creating custom traits")
			}

		}

		log.Debug("openstackplugin/openstack_plugin:UpdateOpenstackTraits() Associating traits to resource")
		err = associateTraitsForResource(&openstackDetails.HostDetails[index], openstackDetails)
		if err != nil {
			return errors.Wrap(err, "openstackplugin/openstack_plugin:UpdateOpenstackTraits() Error in Associating custom traits")
		}

	}

	log.Debug("openstackplugin/openstack_plugin:UpdateOpenstackTraits() Fetch All the custom traits")
	err := getAllCustomTraits(openstackDetails)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:UpdateOpenstackTraits() Error in Fetching all the custom traits for cleanup")
	}

	log.Debug("openstackplugin/openstack_plugin:UpdateOpenstackTraits() Delete All the Non-Associated Traits")
	err = deleteNonAssociatedTraits(openstackDetails)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:UpdateOpenstackTraits() Error in Deleting all the non-associated traits for cleanup")
	}

	log.Info("openstackplugin/openstack_plugin:UpdateOpenstackTraits() Custom traits are updated onto Openstack")

	return nil
}

//getTraitsForResource Get traits for the Openstack Resources
func getTraitsForResource(hostDetails *HostDetails, openstackDetails *OpenstackDetails) error {

	log.Trace("openstackplugin/openstack_plugin:getTraitsForResource() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:getTraitsForResource() Leaving")

	log.Debug("openstackplugin/openstack_plugin:getTraitsForResource() Getting traits for the Openstack resources")
	prefixURL := openstackDetails.Config.Endpoint.URL
	resourceTraitsPath := "resource_providers/" + hostDetails.hostID.String() + "/traits"
	urlPath := prefixURL + resourceTraitsPath
	log.Debug("openstackplugin/openstack_plugin:getTraitsForResource() URL For Resource Traits : " + urlPath)
	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getTraitsForResource() Unable to parse the resource traits path url")
	}

	log.Debug("openstackplugin/openstack_plugin:getTraitsForResource() Sending request to get traits")
	res, err := openstackDetails.OpenstackClient.SendRequest(&openstackClient.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})

	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getTraitsForResource() : Error in getting traits for the Resources")
	}
	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getTraitsForResource() Error in reading response while getting traits for the Resources")
	}

	var openStackTrait model.OpenStackTrait

	log.Debug("openstackplugin/openstack_plugin:getTraitsForResource() Unmarshalling the Openstack traits body")
	err = json.Unmarshal(body, &openStackTrait)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getTraitsForResource(): Error in unmarshalling the Openstack custom traits body")
	}

	for _, trait := range openStackTrait.Traits {

		if !strings.HasPrefix(trait, constants.TraitPrefix) {

			hostDetails.DefaultTraits = append(hostDetails.DefaultTraits, trait)
		}

	}

	hostDetails.ResourceProviderGeneration = openStackTrait.ResourceProviderGeneration
	log.Info("openstackplugin/openstack_plugin:getTraitsForResource() Retrieved the Openstack traits for the resource")

	return nil
}

//createCustomTraits Create Custom Traits
func createCustomTraits(traits []string, openstackDetails *OpenstackDetails) error {

	log.Trace("openstackplugin/openstack_plugin:createCustomTraits() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:createCustomTraits() Leaving")

	for _, trait := range traits {

		prefixURL := openstackDetails.Config.Endpoint.URL
		createTraitsPath := "traits/" + trait
		urlPath := prefixURL + createTraitsPath
		log.Debug("openstackplugin/openstack_plugin:createCustomTraits() Trait Creation URL : " + urlPath)
		parsedUrl, err := url.Parse(urlPath)
		if err != nil {
			return errors.Wrap(err, "openstackplugin/openstack_plugin:createCustomTraits()  Unable to parse the traits path url")
		}

		log.Debug("openstackplugin/openstack_plugin:createCustomTraits() Sending request to create traits")
		res, err := openstackDetails.OpenstackClient.SendRequest(&openstackClient.RequestParams{
			Method: "PUT",
			URL:    parsedUrl,
			Body:   nil,
		})
		if err != nil {
			return errors.Wrap(err, "openstackplugin/openstack_plugin:createCustomTraits() Error in creation of custom traits")
		}

		log.Debug("openstackplugin/openstack_plugin:createCustomTraits() checking the response status code for creating traits")
		if res.StatusCode == http.StatusCreated {
			log.Debug("openstackplugin/openstack_plugin:createCustomTraits() Trait created :" + trait)
		} else if res.StatusCode == http.StatusNoContent {
			log.Debug("openstackplugin/openstack_plugin:createCustomTraits() Trait does not Exist :" + trait)
		} else {
			log.Debug("openstackplugin/openstack_plugin:createCustomTraits() Unable to create Trait :" + trait)
		}
	}

	log.Info("openstackplugin/openstack_plugin:createCustomTraits() Custom traits are created for Openstack")
	return nil
}

//associateTraitsForResource Associate Traits for resource
func associateTraitsForResource(hostDetails *HostDetails, openstackDetails *OpenstackDetails) error {

	log.Trace("openstackplugin/openstack_plugin:associateTraitsForResource() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:associateTraitsForResource() Leaving")

	prefixURL := openstackDetails.Config.Endpoint.URL
	resourceTraitsPath := "resource_providers/" + hostDetails.hostID.String() + "/traits"
	urlPath := prefixURL + resourceTraitsPath
	var openStackTrait model.OpenStackTrait
	openStackTrait.ResourceProviderGeneration = hostDetails.ResourceProviderGeneration

	log.Debug("openstackplugin/openstack_plugin:associateTraitsForResource() Appending the default and custom traits for the resource")
	if hostDetails.trusted {
		openStackTrait.Traits = append(hostDetails.DefaultTraits, hostDetails.CustomTraits...)
	} else {
		openStackTrait.Traits = hostDetails.DefaultTraits
	}

	log.Debug("openstackplugin/openstack_plugin:associateTraitsForResource() Associate Trait URL :  " + urlPath)
	log.Debug("openstackplugin/openstack_plugin:associateTraitsForResource() Resource Provider generation", openStackTrait.ResourceProviderGeneration)
	log.Debug("openstackplugin/openstack_plugin:associateTraitsForResource() OpenStack traits", openStackTrait.Traits)

	log.Debug("openstackplugin/openstack_plugin:associateTraitsForResource() Marshalling the openstack traits into json body")
	jsonBody, err := json.Marshal(openStackTrait)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:associateTraitsForResource() Error in marshalling traits for the resource")
	}
	payload := bytes.NewReader(jsonBody)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:associateTraitsForResource()  Unable to parse the resource traits path url")
	}

	res, err := openstackDetails.OpenstackClient.SendRequest(&openstackClient.RequestParams{
		Method:            "PUT",
		URL:               parsedUrl,
		Body:              payload,
		AdditionalHeaders: map[string]string{"Content-Type": "application/json"},
	})
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:associateTraitsForResource() Error in getting response")
	}

	log.Debug("openstackplugin/openstack_plugin:associateTraitsForResource() checking the response status code for associating traits to resource")
	if res.StatusCode != http.StatusOK {
		return errors.New("openstackplugin/openstack_plugin:associateTraitsForResource() Error in associating traits for the resource :" + string(res.StatusCode))
	}

	log.Info("openstackplugin/openstack_plugin:associateTraitsForResource() Traits are associated to the resource")
	return nil
}

//getAllCustomTraits Get all the custom traits in Openstack
func getAllCustomTraits(openstackDetails *OpenstackDetails) error {
	log.Trace("openstackplugin/openstack_plugin:getAllCustomTraits() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:getAllCustomTraits() Leaving")

	prefixURL := openstackDetails.Config.Endpoint.URL
	resourceTraitsPath := "traits"
	urlPath := prefixURL + resourceTraitsPath
	log.Debug("openstackplugin/openstack_plugin:getAllCustomTraits() The URL for Getting all the traits : " + urlPath)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getAllCustomTraits()  Unable to parse the resource traits path url")
	}
	log.Debug("openstackplugin/openstack_plugin:getAllCustomTraits() Sending request to get all custom traits")
	res, err := openstackDetails.OpenstackClient.SendRequest(&openstackClient.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getAllCustomTraits() : Error in retrieving all the custom triats in Openstack")
	}

	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response")
		}
	}()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getAllCustomTraits() : Error in reading the Openstack custom traits")
	}

	var openStackTrait model.OpenStackTrait
	log.Debug("openstackplugin/openstack_plugin:getAllCustomTraits() unmarshalling the openstack traits")
	err = json.Unmarshal(body, &openStackTrait)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:getAllCustomTraits() : Error in unmarshalling the Openstack custom traits body")
	}
	for _, trait := range openStackTrait.Traits {

		if strings.HasPrefix(trait, constants.TraitPrefix) {
			openstackDetails.AllCustomTraits = append(openstackDetails.AllCustomTraits, trait)
		}

	}
	log.Debug("openstackplugin/openstack_plugin:getAllCustomTraits() The custom traits are :", openstackDetails.AllCustomTraits)

	log.Info("openstackplugin/openstack_plugin:getAllCustomTraits()  Custom traits are received from Openstack endpoint")

	return nil
}

//deleteNonAssociatedTraits Delete all non associated CustomTraits in Openstack
func deleteNonAssociatedTraits(openstackDetails *OpenstackDetails) error {

	log.Trace("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() Leaving")

	for _, trait := range openstackDetails.AllCustomTraits {

		prefixURL := openstackDetails.Config.Endpoint.URL
		resourceTraitsPath := "traits/" + trait
		urlPath := prefixURL + resourceTraitsPath
		log.Debug("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() The Url for deleting all the traits are : " + urlPath)

		parsedUrl, err := url.Parse(urlPath)
		if err != nil {
			return errors.Wrap(err, "openstackplugin/openstack_plugin:deleteNonAssociatedTraits()  Unable to parse the resource traits path url")
		}
		log.Debug("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() Sending request to delete non associated traits")
		res, err := openstackDetails.OpenstackClient.SendRequest(&openstackClient.RequestParams{
			Method:            "DELETE",
			URL:               parsedUrl,
			Body:              nil,
			AdditionalHeaders: map[string]string{"Content-Type": "application/json"},
		})
		if err != nil {
			return errors.Wrap(err, "openstackplugin/openstack_plugin:deleteNonAssociatedTraits() : Error in deleting the non associated traits")
		}
		defer func() {
			derr := res.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing response")
			}
		}()
		log.Debug("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() checking the delete status of non associated traits")
		if res.StatusCode == http.StatusConflict {
			log.Debug("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() The trait " + trait + " is in use by a resource provider.Hence, Skipping the delete.")
		} else {
			log.Debug("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() The trait " + trait + " is Deleted Successfully")
		}
	}
	log.Info("openstackplugin/openstack_plugin:deleteNonAssociatedTraits() Non associated traits are deleted from Openstack endpoint")
	return nil
}

//SendDataToEndPoint pushes host trust data to OpenStack
func SendDataToEndPoint(openstack OpenstackDetails) error {
	log.Trace("openstackplugin/openstack_plugin:SendDataToEndPoint() Entering")
	defer log.Trace("openstackplugin/openstack_plugin:SendDataToEndPoint() Leaving")

	log.Debug("openstackplugin/openstack_plugin:SendDataToEndPoint() Fetching Hosts from Openstack")
	err := GetHostsFromOpenstack(&openstack)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:SendDataToEndPoint() Error in getting Hosts from Openstack")
	}

	log.Debug("openstackplugin/openstack_plugin:SendDataToEndPoint() Filtering Hosts from Openstack")
	for index := range openstack.HostDetails {

		err := FilterHostReportsForOpenstack(&openstack.HostDetails[index], &openstack)
		if err != nil {
			log.WithError(err).Error("openstackplugin/openstack_plugin:SendDataToEndPoint() Error in Filtering Host details for Openstack")
		}
	}

	log.Debug("openstackplugin/openstack_plugin:SendDataToEndPoint() Updating Openstack with the host Details : ", openstack.HostDetails)

	log.Info("openstackplugin/openstack_plugin:SendDataToEndPoint() Updating traits to Openstack")
	err = UpdateOpenstackTraits(&openstack)
	if err != nil {
		return errors.Wrap(err, "openstackplugin/openstack_plugin:SendDataToEndPoint() Error in Filtering Host details for Openstack")
	}

	return nil
}
