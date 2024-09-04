package june2024v2july2024

import (
	"encoding/json"
	"fmt"
	"upgradationScript/june2024v2july2024/july2024"
	"upgradationScript/june2024v2july2024/june2024v2"
)

func supportMultipleInsertion(integratorType string) bool {
	switch integratorType {
	case "jenkins", "docker", "quay", "ecr", "jfrog":
		return true
	default:
		return false
	}
}

func getTranslatedScanName(scanName string) string {
	switch scanName {
	case "compliancescan":
		return "openssfcompliancescan"

	case "sastdastscan":
		return "sastsemgrepscan"

	case "licensescan":
		return "licensescanforcontainers"

	case "sassnykscan", "sastnykscan":
		return "sastsnykscan"

	default:
		return scanName
	}
}

func getValue(integratorType string, scanValue bool) (value string) {
	natureBoolean := false

	switch integratorType {
	case "openssf", "trivy", "grype":
		natureBoolean = true
	case "semgrep", "snyk":
		natureBoolean = false
	}

	if natureBoolean {
		if scanValue {
			return "active"
		}
		return "inactive"
	}

	if scanValue {
		return "Cloud Mode"
	}

	return "Local Mode"
}

func getIntegratorConfigs(integratorType string, yamlIntegratorConfigSchema map[interface{}]interface{}, integratorOldSchemaTypeGrouping map[string][]june2024v2.QueryExistingIntegratorsQueryIntegrator) (output []*july2024.IntegratorConfigsRef, err error) {

	if mapValue, ok := integratorOldSchemaTypeGrouping[integratorType]; ok { //if integrator type exists in old database
		for _, eachEntry := range mapValue {
			var integratorConfigTemp july2024.IntegratorConfigsRef

			var existingIntegratorData map[string]string
			if err = json.Unmarshal([]byte(eachEntry.Credentials.Data), &existingIntegratorData); err != nil {
				err = fmt.Errorf("error: Unmarshal: %s for integrator data from old db: %s", err.Error(), eachEntry.Type)
				return nil, err
			}
			integratorConfigTemp.Name = eachEntry.Name

			var keyConfigs []*july2024.IntegratorKeyValuesRef

			accessLevel := ""
			accessLevelName := ""
			for dataKey, eachParamEntry := range existingIntegratorData { //for each data part of config
				if eachParamEntry == "" {
					continue
				}

				// key change handling for jenkins
				if dataKey == "builduser" {
					dataKey = "approved_user"
				}

				// key change handling for snyk
				if dataKey == "snykorgid" {
					dataKey = "snykOrgId"
				}

				if dataKey == "accessLevel" {
					accessLevel = eachParamEntry
					continue
				}

				if dataKey == "accessLevelName" {
					accessLevelName = eachParamEntry
					continue
				}

				var configKeyTemp july2024.IntegratorKeyValuesRef
				if schemaKeyValue, ok := yamlIntegratorConfigSchema[dataKey]; ok { //get this data key in new schema map
					mapEachConfigData := schemaKeyValue.(map[interface{}]interface{})
					if encryptValue, ok := mapEachConfigData["encrypt"]; ok {
						ptr := encryptValue.(bool)
						configKeyTemp.Encrypt = &ptr
					}
				} else {
					err = fmt.Errorf("error: key: %s for integrator type: %s not found", dataKey, integratorType)
					return nil, err
				}
				configKeyTemp.Key = dataKey
				configKeyTemp.Value = eachParamEntry
				keyConfigs = append(keyConfigs, &configKeyTemp)
			}

			if integratorType == "bitbucket" {
				if accessLevel != "" && accessLevelName != "" {
					dataKey := ""
					dataValue := accessLevelName
					switch accessLevel {
					case "workspace":
						dataKey = "workspaceId"
					case "project":
						dataKey = "Project"
					case "repository":
						dataKey = "Repository"
					}

					encryptFalse := false
					keyConfigs = append(keyConfigs, &july2024.IntegratorKeyValuesRef{
						Key:     dataKey,
						Value:   dataValue,
						Encrypt: &encryptFalse,
					})
				} else {
					return nil, fmt.Errorf("accessLevel or accessLevelName not found in bitbucket integrator")
				}
			}

			integratorConfigTemp.Configs = keyConfigs
			output = append(output, &integratorConfigTemp)
		}
	}
	return output, nil
}

func getFeatureConfigs(integratorType, category string, featureModeOldSchemaTypeGrouping map[string][]june2024v2.QueryFeatureModeQueryFeatureMode) (output []*july2024.FeatureModeRef) {

	if mapValue, ok := featureModeOldSchemaTypeGrouping[integratorType]; ok {
		for _, eachEntry := range mapValue {

			var featureModeTemp july2024.FeatureModeRef

			featureModeTemp.Organization.Id = eachEntry.Organization.Id
			featureModeTemp.Key = getTranslatedScanName(eachEntry.Scan)
			featureModeTemp.CreatedAt = eachEntry.CreatedAt
			featureModeTemp.UpdatedAt = eachEntry.UpdatedAt
			featureModeTemp.Category = category
			featureModeTemp.Value = getValue(integratorType, *eachEntry.Enabled)

			output = append(output, &featureModeTemp)

		}
	}
	return output
}
