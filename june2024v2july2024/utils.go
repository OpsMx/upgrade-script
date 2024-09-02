package june2024v2july2024

import (
	"encoding/json"
	"upgradationScript/june2024v2july2024/july2024"
	"upgradationScript/june2024v2july2024/june2024v2"
	"upgradationScript/logger"
)

func supportMultipleInsertion(integratorType string) (areSupported bool) {
	switch integratorType {
	case "jenkins", "docker", "quay", "ecr", "jfrog":
		areSupported = true
	default:
		areSupported = false
	}
	return areSupported
}

func getIntegratorConfigs(integratorType string, yamlIntegratorConfigSchema map[string]interface{}, integratorOldSchemaTypeGrouping map[string][]june2024v2.QueryExistingIntegratorsQueryIntegrator) (output []*july2024.IntegratorConfigsRef) {

	if mapValue, ok := integratorOldSchemaTypeGrouping[integratorType]; ok { //if integrator type exists in old database
		for _, eachEntry := range mapValue {
			var integratorConfigTemp july2024.IntegratorConfigsRef

			var existingIntegratorData map[string]string
			if err := json.Unmarshal([]byte(eachEntry.Credentials.Data), &existingIntegratorData); err != nil {
				logger.Sl.Errorf("error: Unmarshal: %s for integrator data from old db: %s", err.Error(), eachEntry.Type)
				continue
			}
			integratorConfigTemp.Name = eachEntry.Name

			var keyConfigs []*july2024.IntegratorKeyValuesRef

			for dataKey, eachParamEntry := range existingIntegratorData { //for each data part of config
				var configKeyTemp july2024.IntegratorKeyValuesRef
				if schemaKeyValue, ok := yamlIntegratorConfigSchema[dataKey]; ok { //get this data key in new schema map
					mapEachConfigData := schemaKeyValue.(map[string]interface{})
					if encryptValue, ok := mapEachConfigData["encrypt"]; ok {
						ptr := encryptValue.(bool)
						configKeyTemp.Encrypt = &ptr
					}
				}
				configKeyTemp.Key = dataKey
				configKeyTemp.Value = eachParamEntry
				keyConfigs = append(keyConfigs, &configKeyTemp)
			}
			integratorConfigTemp.Configs = keyConfigs
			output = append(output, &integratorConfigTemp)
		}
	} else {
		var integratorConfigTemp july2024.IntegratorConfigsRef

		var keyConfigs []*july2024.IntegratorKeyValuesRef

		for schemaConfigKey, eachParamEntry := range yamlIntegratorConfigSchema {
			var configKeyTemp july2024.IntegratorKeyValuesRef
			mapEachConfigData := eachParamEntry.(map[string]interface{})
			if encryptValue, ok := mapEachConfigData["encrypt"]; ok {
				ptr := encryptValue.(bool)
				configKeyTemp.Encrypt = &ptr
			}

			configKeyTemp.Key = schemaConfigKey
			keyConfigs = append(keyConfigs, &configKeyTemp)
		}
		integratorConfigTemp.Configs = keyConfigs
		output = append(output, &integratorConfigTemp)
	}
	return output
}

func getFeatureConfigs(integratorType string, yamlFeatureConfigSchema map[string]interface{}, featureModeOldSchemaTypeGrouping map[string][]june2024v2.QueryFeatureModeQueryFeatureMode) (output []*july2024.FeatureModeRef) {

	if mapValue, ok := featureModeOldSchemaTypeGrouping[integratorType]; ok {
		for _, eachEntry := range mapValue {

			for key, eachConfigData := range yamlFeatureConfigSchema {
				var featureModeTemp july2024.FeatureModeRef

				featureModeTemp.Organization.Id = eachEntry.Organization.Id
				featureModeTemp.Key = key
				featureModeTemp.CreatedAt = eachEntry.CreatedAt
				featureModeTemp.UpdatedAt = eachEntry.UpdatedAt

				mapEachConfigData := eachConfigData.(map[string]interface{})
				if defaultValue, ok := mapEachConfigData["default"]; ok {
					featureModeTemp.Value = defaultValue.(string)
				}
				output = append(output, &featureModeTemp)
			}
		}
	} else {

		for key, eachConfigData := range yamlFeatureConfigSchema {
			var featureModeTemp july2024.FeatureModeRef

			featureModeTemp.Key = key

			mapEachConfigData := eachConfigData.(map[string]interface{})
			if defaultValue, ok := mapEachConfigData["default"]; ok {
				featureModeTemp.Value = defaultValue.(string)
			}
			output = append(output, &featureModeTemp)
		}

	}
	return output
}
