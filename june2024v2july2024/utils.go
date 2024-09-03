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

func getTranslatedScanName(scanName string) (newScanName string) {
	switch scanName {
	case "compliancescan":
		newScanName = "openssfcompliancescan"
	case "sastdastscan":
		newScanName = "sastsemgrepscan"
	case "licensescan":
		newScanName = "licensescanforcontainers"
	case "sastsonarscan":
		newScanName = "sonarqubeFileInsertion"
	default:
		newScanName = scanName
	}
	return newScanName
}

func getValue(scanName string) (value string) {
	switch scanName {
	case "sonarqubeFileInsertion", "vulnerabilityscan":
		value = "inactive"
	case "sastsnykscan", "sastsemgrepscan", "sastcodacyscan":
		value = "Local Mode"
	case "bitbucketAuthMode":
		value = "bearer"
	case "accessLevel":
		value = "Workspace"
	default:
		value = "active"
	}
	return value
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

			for dataKey, eachParamEntry := range existingIntegratorData { //for each data part of config
				if eachParamEntry == "" {
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
					err = fmt.Errorf("error: key: %s for fetaure mode not found", dataKey)
					return nil, err
				}
				configKeyTemp.Key = dataKey
				configKeyTemp.Value = eachParamEntry
				keyConfigs = append(keyConfigs, &configKeyTemp)
			}
			integratorConfigTemp.Configs = keyConfigs
			output = append(output, &integratorConfigTemp)
		}
	}
	return output, nil
}

func getFeatureConfigs(integratorType string, yamlFeatureConfigSchema map[interface{}]interface{}, featureModeOldSchemaTypeGrouping map[string][]june2024v2.QueryFeatureModeQueryFeatureMode) (output []*july2024.FeatureModeRef) {

	if mapValue, ok := featureModeOldSchemaTypeGrouping[integratorType]; ok {
		for _, eachEntry := range mapValue {

			for key, eachConfigData := range yamlFeatureConfigSchema {
				var featureModeTemp july2024.FeatureModeRef

				featureModeTemp.Organization.Id = eachEntry.Organization.Id
				featureModeTemp.Key = key.(string)
				featureModeTemp.CreatedAt = eachEntry.CreatedAt
				featureModeTemp.UpdatedAt = eachEntry.UpdatedAt

				mapEachConfigData := eachConfigData.(map[interface{}]interface{})
				if defaultValue, ok := mapEachConfigData["default"]; ok {
					featureModeTemp.Value = defaultValue.(string)
				}
				output = append(output, &featureModeTemp)
			}
		}
	}
	return output
}

const schemaYaml = `
integrationData:
  - stage: Source
    integrations:
      - integratorType: gitlab
        category: sourcetool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
      - integratorType: github
        category: sourcetool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
      - integratorType: bitbucket
        category: sourcetool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
          username:
            encrypt: false
          password:
            encrypt: true
          workspaceId:
            encrypt: false
          projectKey:
            encrypt: false
          repository:
            encrypt: false
        featureConfigs:
          bitbucketAuthMode:
            default: bearer
          accessLevel:
            default: Workspace
      - integratorType: sonarqube
        category: scanningtool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
        featureConfigs:
          sonarqubeFileInsertion:
            default: inactive
      - integratorType: openssf
        category: scanningtool
        featureConfigs:
          openssfcompliancescan:
            default: active
      - integratorType: virustotal
        category: sourcetool
        integratorConfigs:
          token:
            encrypt: true
      - integratorType: snyk
        category: sourcetool
        integratorConfigs:
          snykOrgId:
            encrypt: false
          token:
            encrypt: true
          url:
            encrypt: false
        featureConfigs:
          sastsnykscan:
            default: Local Mode
      - integratorType: semgrep
        category: sourcetool
        integratorConfigs:
          token:
            encrypt: true
        featureConfigs:
          sastsemgrepscan:
            default: Local Mode
      - integratorType: codacy
        category: sourcetool
        integratorConfigs:
          token:
            encrypt: true
        featureConfigs:
          sastcodacyscan:
            default: Local Mode
  - stage: Build
    integrations:
      - integratorType: jenkins
        category: citool
        integratorConfigs:
          url:
            encrypt: false
          approved_user:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
  - stage: Artifact
    integrations:
      - integratorType: trivy
        category: scanningtool
        featureConfigs:
          vulnerabilityscan:
            default: active
          helmscan:
            default: active
          secretscanforsource:
            default: active
          secretscanforcontainers:
            default: active
          licensescanforsource:
            default: active
          licensescanforcontainers:
            default: active
      - integratorType: docker
        category: dockerregistry
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
      - integratorType: ecr
        category: dockerregistry
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          region:
            encrypt: false
          awsAccessKey:
            encrypt: true
          awsSecretKey:
            encrypt: true
      - integratorType: quay
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
      - integratorType: jfrog
        category: dockerregistry
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
      - integratorType: google-artifact-registry
        category: aptregistry
        integratorConfigs:
          key:
            encrypt: true
          source:
            encrypt: false
      - integratorType: grype
        category: scanningtool
        featureConfigs:
          vulnerabilityscan:
            default: inactive
  - stage: Others
    integrations:
      - integratorType: chatgpt
        category: communications
        integratorConfigs:
          token:
            encrypt: true
      - integratorType: slack
        category: communications
        integratorConfigs:
          channel:
            encrypt: false
          token:
            encrypt: true
      - integratorType: jira
        category: communications
        integratorConfigs:
          projectKey:
            encrypt: false
          username:
            encrypt: false
          url:
            encrypt: false
          token:
            encrypt: true
      - integratorType: custompolicy
        category: managementtool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
`
