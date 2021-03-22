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
	"github.com/intel-secl/intel-secl/v3/pkg/flavorgen/version"
	controller "github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	hcType "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"

	"github.com/antchfx/jsonquery"
)

type FlavorGen struct{}

var flavortemplateargs Templates

type Templates []string

//Schema location constansts
const (
	commonDefinitionsSchema = "/etc/flavorgen/schema/common.schema.json"
	flavorTemplateSchema    = "/etc/flavorgen/schema/flavor-template.json"
)

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

	//read the host manifest json
	hostManifestJSON, err := readJson(manifestFilepath)
	if err != nil {
		return hcType.HostManifest{}, nil, errors.New("flavorgen/flavor_gen:processJsonFile() Could not read host manifest json")
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

		//read the flavor template json
		flavorJSON, err := readJson(template)
		if err != nil {
			return hcType.HostManifest{}, nil, errors.Wrap(err, "flavorgen/flavor_gen:processJsonFile() Could not read flavor template json")
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

flavorgen <command> [arguments]
	
Available Commands:
	-f                     To provide Flavor template json file
	-m                     To provide Hostmanifest json file
	help|-h|--help         Show this help message
	-log                   To log the execution
	-version               print the current version
`

func validateTemplate(templateFilePath string) (string, error) {
	defaultLog.Trace("flavorgen/flavor_gen:validate_Template() Entering")
	defer defaultLog.Trace("flavorgen/flavor_gen:validate_Template() Leaving")

	var ftc controller.FlavorTemplateController
	var flavorTemplate hvs.FlavorTemplate

	template, err := ioutil.ReadFile(templateFilePath)
	if err != nil {
		return "Unable to read flavor template json", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to read flavor template json")
	}

	//Restore the request body to it's original state
	flavorTemplateJson := ioutil.NopCloser(bytes.NewBuffer(template))

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(flavorTemplateJson)
	dec.DisallowUnknownFields()

	err = dec.Decode(&flavorTemplate)
	if err != nil {
		fmt.Println(err)
		return "Unable to decode flavor template json", errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to decode flavor template json")
	}

	ftc.CommonDefinitionsSchema = commonDefinitionsSchema
	ftc.FlavorTemplateSchema = flavorTemplateSchema

	//call the ValidateFlavorTemplateCreateRequest method from flavortemplate_controller.go to validate the flavor template
	errMsg, err := ftc.ValidateFlavorTemplateCreateRequest(flavorTemplate, string(template))
	if err != nil {
		fmt.Println(err)
		return errMsg, errors.Wrap(err, "flavorgen/flavor_gen:validate_Template() Unable to create flavor template, validation failed")
	}

	return "", nil
}

func (flavorgen FlavorGen) GenerateFlavors() {
	// Defining option flags with three arguments:
	// the flag's name, the default value, and a short description (displayed whith the option --help)
	flag.Var(&flavortemplateargs, "f", "flavor-template json file")
	manifestFilePath := flag.String("m", "", "host-manifest json file")
	versionFlag := flag.Bool("version", false, "Print the current version and exit")

	// Showing useful information when the user enters the --help option
	flag.Usage = func() {
		fmt.Print(helpStr)
	}
	flag.Parse()

	if *versionFlag {
		fmt.Println("Current build version: ", version.Version)
		fmt.Println("Build date: ", version.BuildDate)
		os.Exit(1)
	}

	// Check for both manfest and flavor template
	if *manifestFilePath == "" && len(flavortemplateargs) == 0 {
		fmt.Printf(helpStr)
		exitGracefully(errors.New("Manifest file path and flavor template path missing"))
	} else if *manifestFilePath == "" {
		exitGracefully(errors.New("Manifest file path missing"))
	} else if len(flavortemplateargs) == 0 {
		exitGracefully(errors.New("Flavor template path missing"))
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

	var rp types.PlatformFlavor
	switch strings.ToUpper(strings.TrimSpace(hostmanifest.HostInfo.OSName)) {
	case constants.OsVMware:
		rp = types.NewESXPlatformFlavor(&hostmanifest, nil, flavorTemplates)
	// Fallback to Linux
	default:
		rp = types.NewLinuxPlatformFlavor(&hostmanifest, nil, flavorTemplates)
	}

	// Create the flavor json
	err = createFlavor(rp)
	if err != nil {
		defaultLog.Info("flavorgen/flavor_gen:main() Unable to create flavorpart(s) %s", err)
		exitGracefully(errors.New("Unable to create flavorpart(s)"))
	}
}

//readJson method is used to read the file from input file path and validate
func readJson(filePath string) ([]byte, error) {
	// Read the input file
	inputJson, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "flavorgen/flavor_gen:readJson() Could not load the input file")
	}

	if len(inputJson) == 0 {
		return nil, errors.New("flavorgen/flavor_gen:readJson() Empty file given, unable to proceed further")
	}

	// Validate the format
	if !json.Valid(inputJson) {
		return nil, errors.New("flavorgen/flavor_gen:readJson() Given file is not a valid json")
	}

	return inputJson, nil
}
