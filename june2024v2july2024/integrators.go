package june2024v2july2024

import (
	"context"
	"fmt"
	"os"
	"time"
	"upgradationScript/june2024v2july2024/july2024"
	"upgradationScript/june2024v2july2024/june2024v2"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
	"gopkg.in/yaml.v2"
)

func performIntegratorsTransition(prodDgraphClient, expDgraphClient graphql.Client) error {

	ctx := context.Background()

	existingFeatureModes, err := june2024v2.QueryFeatureMode(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: QueryFeatureMode: could'nt query old prod features to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Existing feature mode transition in old db %d -----------------", len(existingFeatureModes.QueryFeatureMode))

	featureModeOldSchemaTypeGrouping := make(map[string][]june2024v2.QueryFeatureModeQueryFeatureMode)

	if len(existingFeatureModes.QueryFeatureMode) > 0 {

		for _, eachFeatureMode := range existingFeatureModes.QueryFeatureMode {

			if val, ok := featureModeOldSchemaTypeGrouping[eachFeatureMode.Type]; ok {
				val = append(val, *eachFeatureMode)
				featureModeOldSchemaTypeGrouping[eachFeatureMode.Type] = val
			} else {
				featureModeOldSchemaTypeGrouping[eachFeatureMode.Type] = []june2024v2.QueryFeatureModeQueryFeatureMode{*eachFeatureMode}
			}
		}
	}

	existingIntegrators, err := june2024v2.QueryExistingIntegrators(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: QueryExistingIntegrators: could'nt query old prod integrators to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Existing integrators configs transition in old db %d -----------------", len(existingIntegrators.QueryIntegrator))

	integratorOldSchemaTypeGrouping := make(map[string][]june2024v2.QueryExistingIntegratorsQueryIntegrator)

	if len(existingIntegrators.QueryIntegrator) == 0 {

		for _, eachIntegrator := range existingIntegrators.QueryIntegrator {

			if val, ok := integratorOldSchemaTypeGrouping[eachIntegrator.Type]; ok {

				if supportMultipleInsertion(eachIntegrator.Type) {
					val = append(val, *eachIntegrator)
					integratorOldSchemaTypeGrouping[eachIntegrator.Type] = val
				}
			} else {
				integratorOldSchemaTypeGrouping[eachIntegrator.Type] = []june2024v2.QueryExistingIntegratorsQueryIntegrator{*eachIntegrator}
			}
		}
	}

	filepath := "schema.yaml"
	integrationStages, err := readAndUnmarshalyaml(filepath)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: readAndUnmarshalyaml: error %s", err.Error())
	}

	if len(integrationStages) == 0 {
		return fmt.Errorf("yaml doesn't contain integrations details: filepath: %s", filepath)
	}

	var translatedInput []*july2024.AddIntegratorInput
	for _, eachStage := range integrationStages {
		for _, eachIntegrator := range eachStage.Integrations {

			var newTranslatedIntegrator july2024.AddIntegratorInput
			convMap := eachIntegrator.(map[string]interface{})
			currTime := time.Now()
			newTranslatedIntegrator.CreatedAt = &currTime
			newTranslatedIntegrator.UpdatedAt = &currTime

			if mapValue, ok := convMap["integratorType"].(string); ok {
				newTranslatedIntegrator.Type = mapValue
			}

			if mapValue, ok := convMap["category"].(string); ok {
				newTranslatedIntegrator.Category = mapValue
			}

			if len(integratorOldSchemaTypeGrouping) > 0 {
				newTranslatedIntegrator.Organization.Id = integratorOldSchemaTypeGrouping[newTranslatedIntegrator.Type][0].Organization.Id
			}

			integratorConfigMapValue, integratorConfigsExists := convMap["integratorConfigs"]
			if integratorConfigsExists {
				integratorConfigData := integratorConfigMapValue.(map[string]interface{})
				newTranslatedIntegrator.IntegratorConfigs = getIntegratorConfigs(newTranslatedIntegrator.Type, integratorConfigData, integratorOldSchemaTypeGrouping)
			}

			if len(featureModeOldSchemaTypeGrouping) > 0 {
				newTranslatedIntegrator.Organization.Id = featureModeOldSchemaTypeGrouping[newTranslatedIntegrator.Type][0].Organization.Id
			}

			featureConfigMapValue, featureConfigsExists := convMap["featureConfigs"]
			if featureConfigsExists {
				featureConfigsData := featureConfigMapValue.(map[string]interface{})
				newTranslatedIntegrator.FeatureConfigs = getFeatureConfigs(newTranslatedIntegrator.Type, featureConfigsData, featureModeOldSchemaTypeGrouping)
			}

			if featureConfigsExists && !integratorConfigsExists {
				newTranslatedIntegrator.Status = "connected"
			} else if integratorConfigsExists && len(newTranslatedIntegrator.IntegratorConfigs) > 0 {
				newTranslatedIntegrator.Status = "connected"
			} else if integratorConfigsExists && len(newTranslatedIntegrator.IntegratorConfigs) == 0 {
				newTranslatedIntegrator.Status = "disabled"
			}

			translatedInput = append(translatedInput, &newTranslatedIntegrator)
		}
	}

	logger.Sl.Debug("adding Integrators to the database")

	if _, err := july2024.AddIntegrator(ctx, expDgraphClient, translatedInput); err != nil {
		return fmt.Errorf("error: performIntegratorsTransition: AddIntegrator error: %s", err.Error())
	}
	logger.Sl.Debug("added Integrators to the database")

	logger.Logger.Info("------------Integrators upgrade complete-------------------------")
	return nil
}

func readAndUnmarshalyaml(filepath string) (IntegrationStages, error) {
	readData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error: ReadFile: filepath: %s , %s", filepath, err.Error())
	}

	var decodedData ConfigData
	if err := yaml.Unmarshal(readData, &decodedData); err != nil {
		return nil, fmt.Errorf("error: Unmarshal: ConfigData: %s", err.Error())
	}

	subField := decodedData.Data.SSDIntegrationsYAML.(string)

	var configs SSDIntegrations
	if err := yaml.Unmarshal([]byte(subField), &configs); err != nil {
		return nil, fmt.Errorf("error: Unmarshal: SSDIntegrations: %s", err.Error())
	}

	return configs.IntegrationData, nil
}
