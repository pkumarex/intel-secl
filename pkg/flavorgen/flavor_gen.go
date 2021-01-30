/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavorgen

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	hcType "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/xeipuuv/gojsonschema"

	"github.com/antchfx/jsonquery"
)

type FlavorGen struct{}

var flavortemplateargs Templates

type Templates []string

// exitGracefully performs exit the from the tool
func exitGracefully(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// String is the method to format the flag's value, part of the flag.Value interface.
// The String method's output will be used in diagnostics.
func (templates *Templates) String() string {
	return fmt.Sprint(*templates)
}

// Set is the method to set the flag value, part of the flag.Value interface.
// Set's argument is a string to be parsed to set the flag.
// It's a comma-separated list, so we split it.
func (templates *Templates) Set(value string) error {
	// If we wanted to allow the flag to be set multiple times,
	// accumulating values, we would delete this if statement.
	// That would permit usages such as
	//	-f xx.json -f yy.json
	// and other combinations.
	for _, template := range strings.Split(value, ",") {
		*templates = append(*templates, template)
	}
	
	return nil
}

// processJsonFile is used to process the hostmanifest and flavor templates
// Returns error if could not load the files
// Returns error if not valid json
// Returns error if could not unmarshall the json
// Returns error if all flavor template condition not matches
func processJsonFile(manifestFilepath string, flavorTemplates []string) (hcType.HostManifest, []hvs.FlavorTemplate, error) {
	defaultLog.Trace("flavorgen/flavor_gen:processJsonFile() Entering")
	defer defaultLog.Trace("flavorgen/flavor_gen:processJsonFile() Leaving")

	var hostManifest hcType.HostManifest
	var flavors []hvs.FlavorTemplate

	// Read the hostmanifestfile
	hostManifestJSON, err := ioutil.ReadFile(manifestFilepath)
	if err != nil {
		return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Could not load host manifest file")
	}

	if len(hostManifestJSON) == 0 {
		return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Empty hostmanifest file given, unable to proceed further")
	}

	// Validate the format
	if !json.Valid(hostManifestJSON) {
		return hcType.HostManifest{}, nil, errors.New("flavorgen/flavor_gen:processJsonFile() Hostmanifest file is not a valid json")
	}
	err = json.Unmarshal(hostManifestJSON, &hostManifest)
	if err != nil {
		fmt.Errorf("Could not unmarshal host manifest json %s", err)
		return hcType.HostManifest{}, nil, errors.New("flavorgen/flavor_gen:processJsonFile() Could not unmarshal host manifest json")
	}

	manifest, err := jsonquery.Parse(bytes.NewReader(hostManifestJSON))
	if err != nil {
		fmt.Errorf("Could not parse host manifest json %s", err)
		return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Could not parse host manifest json")
	}

	for _, template := range flavorTemplates {
		var flavorTemplate hvs.FlavorTemplate
		flavorJSON, err := ioutil.ReadFile(template)
		if err != nil {
			return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Could not load flavor template file")
		}

		if len(flavorJSON) == 0 {
			return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Empty flavor template file is given, unable to proceed further")
		}

		// Validate the format
		if !json.Valid(flavorJSON) {
			return hcType.HostManifest{}, nil, errors.New("flavorgen/flavor_gen:processJsonFile() Given flavor template file is not a valid json")
		}

		err = json.Unmarshal(flavorJSON, &flavorTemplate)
		if err != nil {
			return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Could not unmarshal flavor template json")
		}

		if flavorTemplate.ID == uuid.Nil {
			flavorTemplate.ID, err = uuid.NewRandom()
			if err != nil {
				return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Failed to generate UUID for flavor template")
			}
		}

		conditionEval := false
		for _, condition := range flavorTemplate.Condition {
			expectedData, err := jsonquery.Query(manifest, condition)
			if err != nil {
				return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Failed to query search condition with hostmanifest")
			}
			if expectedData == nil {
				fmt.Println(flavorTemplate.Condition)
				conditionEval = true
				break
			}
		}
		if !conditionEval {
			flavors = append(flavors, flavorTemplate)
		}
	}
	if len(flavors) == 0 {
		return hcType.HostManifest{}, nil, errors.New("flavorgen/flavor_gen:processJsonFile() Condition does not matches with manifest file")
	}

	return hostManifest, flavors, nil
}

// checkIfValidFile to check the given file exists and in proper format
func checkIfValidFile(filename string) (bool, error) {
	defaultLog.Trace("flavorgen/flavor_gen:checkIfValidFile() Entering")
	defer defaultLog.Trace("flavorgen/flavor_gen:checkIfValidFile() Leaving")

	// Checking if entered file is json by using the filepath package
	if fileExtension := filepath.Ext(filename); fileExtension != ".json" {
		return false, fmt.Errorf("File %s is not json", filename)
	}

	// Checking if filepath entered belongs to an existing file.
	if _, err := os.Stat(filename); err != nil && os.IsNotExist(err) {
		return false, fmt.Errorf("File %s does not exist", filename)
	}

	// If we get to this point, it means this is a valid file
	return true, nil
}

const helpStr = `Usage:

flavor-gen <command> [arguments]
	
Available Commands:
	-f                     To provide Flavor template json file
	-m                     To provide Hostmanifest json file
	help|-h|--help         Show this help message
	-log                   To log the execution

`

func validateTemplate(templateFilePath string) (string, error) {
	defaultLog.Trace("flavorgen/flavor_gen:validate_Template() Entering")
	defer defaultLog.Trace("flavorgen/flavor_gen:validate_Template() Leaving")

	template, err := ioutil.ReadFile(templateFilePath)
	if err != nil {
		return "Unable to read flavor template json", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to read flavor template json")
	}

	//Restore the request body to it's original state
	flavorTemplateJson := ioutil.NopCloser(bytes.NewBuffer(template))

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(flavorTemplateJson)
	dec.DisallowUnknownFields()

	var flavorTemplate hvs.FlavorTemplate

	err = dec.Decode(&flavorTemplate)
	if err != nil {
		fmt.Println(err)
		return "Unable to decode flavor template json", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to decode flavor template json")
	}

	// Check whether the template is adhering to the schema
	schemaLoader := gojsonschema.NewSchemaLoader()

	definitionsSchema := gojsonschema.NewStringLoader(commonDefinitionsSchema)

	flvrTemplateSchema := gojsonschema.NewStringLoader(flavorTemplateSchema)
	schemaLoader.AddSchemas(definitionsSchema)

	schema, err := schemaLoader.Compile(flvrTemplateSchema)
	if err != nil {
		fmt.Println(err)
		return "Unable to Validate the template", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to compile the schemas")
	}

	documentLoader := gojsonschema.NewBytesLoader(template)

	result, err := schema.Validate(documentLoader)
	if err != nil {
		fmt.Println(err)
		return "Unable to Validate the template", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to validate the template")
	}

	var errorMsg string
	if !result.Valid() {
		for _, desc := range result.Errors() {
			errorMsg = errorMsg + fmt.Sprintf("- %s\n", desc)
		}
		return errorMsg, errors.New("flavorgen/flavor_gen:validate_Template() The provided template is not valid" + errorMsg)
	}

	//Validation the syntax of the conditions
	tempDoc, err := jsonquery.Parse(strings.NewReader("{}"))
	if err != nil {
		return "Error parsing the json", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Error parsing the json")
	}
	for _, condition := range flavorTemplate.Condition {
		_, err := jsonquery.Query(tempDoc, condition)
		if err != nil {
			return "Invalid syntax in condition statement", errors.Wrapf(err, "flavorgen/flavor_gen:validate_Template() Invalid syntax in condition : %s", condition)
		}
	}

	//Check whether each pcr index is associated with not more than one bank.
	pcrMap := make(map[*hvs.FlavorPart][]hvs.PCR)
	flavors := []*hvs.FlavorPart{flavorTemplate.FlavorParts.Platform, flavorTemplate.FlavorParts.OS, flavorTemplate.FlavorParts.HostUnique, flavorTemplate.FlavorParts.Software}
	for _, flavor := range flavors {
		if flavor != nil {
			if _, ok := pcrMap[flavor]; !ok {
				var pcrs []hvs.PCR
				for _, pcrRule := range flavor.PcrRules {
					pcrs = append(pcrs, pcrRule.Pcr)
				}
				pcrMap[flavor] = pcrs
			}
		}
	}

	for _, pcrList := range pcrMap {
		temp := make(map[int]bool)
		for _, pcr := range pcrList {
			if _, ok := temp[pcr.Index]; !ok {
				temp[pcr.Index] = true
			} else {
				return "Template has duplicate banks for same PCR index", errors.New("flavorgen/flavor_gen:validate_Template() Template has duplicate banks for same PCR index")
			}
		}
	}

	return "", nil
}

func (flavorgen FlavorGen) GenerateFlavors() {

	// Defining option flags with three arguments:
	// the flag's name, the default value, and a short description (displayed whith the option --help)
	flag.Var(&flavortemplateargs, "f", "flavor-template json file")
	manifestFilePath := flag.String("m", "", "host-manifest json file")

	// Showing useful information when the user enters the --help option
	flag.Usage = func() {
		fmt.Print(helpStr)
	}
	flag.Parse()

	// Check for both manfest and flavor template
	if *manifestFilePath == "" || len(flavortemplateargs) == 0 {
		fmt.Printf(helpStr)
		if *manifestFilePath == "" && len(flavortemplateargs) == 0 {
			exitGracefully(errors.New("Manifest file path and flavor template path missing"))
		} else if *manifestFilePath == "" {
			exitGracefully(errors.New("Manifest file path missing"))
		} else if len(flavortemplateargs) == 0 {
			exitGracefully(errors.New("Flavor template path missing"))
		}
	}

	// Validating the Manifest file entered
	if valid, err := checkIfValidFile(*manifestFilePath); err != nil && !valid {
		defaultLog.Info("flavorgen/flavor_gen:main() Not a valid hostmanifest file %s", err)
		exitGracefully(errors.New("Not a valid hostmanifest file: " + *manifestFilePath))
	}

	// Validating the template file entered
	for _, template := range flavortemplateargs {
		if valid, err := checkIfValidFile(template); err != nil && !valid {
			defaultLog.Info("flavorgen/flavor_gen:main() Not a valid template file %s", err)
			exitGracefully(errors.New("Not a valid template file: " + template))
		}
		errMsg, err := validateTemplate(template)
		if err != nil {
			defaultLog.Info("flavorgen/flavor_gen:main() Error in validating the Template %s", err)
			exitGracefully(errors.New(errMsg))
		}
	}

	// Process the host manifest and flavor template
	hostmanifest, flavorTemplates, err := processJsonFile(*manifestFilePath, flavortemplateargs)
	if err != nil {
		fmt.Println(err)
		defaultLog.Info("flavorgen/flavor_gen:main() Error finding matching templates %s", err)
		exitGracefully(errors.New("Error finding matching templates"))
	}

	linuxPlatformFlavor := types.NewLinuxPlatformFlavor(&hostmanifest, nil, flavorTemplates)

	// Create the flavor json
	err = createFlavor(linuxPlatformFlavor)
	if err != nil {
		defaultLog.Info("flavorgen/flavor_gen:main() Unable to create flavorpart(s) %s", err)
		exitGracefully(errors.New("Unable to create flavorpart(s)"))
	}
}
