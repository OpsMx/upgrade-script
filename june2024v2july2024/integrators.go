package june2024v2july2024

import (
	"context"
	"fmt"
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

	logger.Sl.Debugf("-----------Number Of Existing feature mode transition in old db: %d -------------", len(existingFeatureModes.QueryFeatureMode))

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

	logger.Sl.Debugf("----------Number Of Existing integrators configs transition in old db %d --------------", len(existingIntegrators.QueryIntegrator))

	integratorOldSchemaTypeGrouping := make(map[string][]june2024v2.QueryExistingIntegratorsQueryIntegrator)
	var orgId string
	if len(existingIntegrators.QueryIntegrator) == 0 {

		for _, eachIntegrator := range existingIntegrators.QueryIntegrator {

			if val, ok := integratorOldSchemaTypeGrouping[eachIntegrator.Type]; ok {

				if supportMultipleInsertion(eachIntegrator.Type) {
					val = append(val, *eachIntegrator)
					integratorOldSchemaTypeGrouping[eachIntegrator.Type] = val
					continue
				}
				return fmt.Errorf("multiple integrator not supported for this type: %s discrepancy in existing data", eachIntegrator.Type)
			} else {
				integratorOldSchemaTypeGrouping[eachIntegrator.Type] = []june2024v2.QueryExistingIntegratorsQueryIntegrator{*eachIntegrator}
				orgId = eachIntegrator.Organization.Id
			}
		}

	}

	integrationStages, err := readAndUnmarshalyaml()
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: readAndUnmarshalyaml: error %s", err.Error())
	}

	var translatedInput []*july2024.AddIntegratorInput
	for _, eachStage := range integrationStages {
		for _, eachIntegrator := range eachStage.Integrations {

			var newTranslatedIntegrator july2024.AddIntegratorInput
			convMap := eachIntegrator.(map[interface{}]interface{})
			currTime := time.Now()
			newTranslatedIntegrator.CreatedAt = &currTime
			newTranslatedIntegrator.UpdatedAt = &currTime
			newTranslatedIntegrator.Organization.Id = orgId

			if mapValue, ok := convMap["integratorType"]; ok {
				newTranslatedIntegrator.Type = mapValue.(string)
			}

			if mapValue, ok := convMap["category"]; ok {
				newTranslatedIntegrator.Category = mapValue.(string)
			}

			integratorConfigMapValue, integratorConfigsExists := convMap["integratorConfigs"]
			if integratorConfigsExists {
				var err error
				integratorConfigData := integratorConfigMapValue.(map[interface{}]interface{})
				newTranslatedIntegrator.IntegratorConfigs, err = getIntegratorConfigs(newTranslatedIntegrator.Type, integratorConfigData, integratorOldSchemaTypeGrouping)
				if err != nil {
					return fmt.Errorf("performIntegratorsTransition: getIntegratorConfigs: error %s", err.Error())
				}
			}

			featureConfigMapValue, featureConfigsExists := convMap["featureConfigs"]
			if featureConfigsExists {
				featureConfigsData := featureConfigMapValue.(map[interface{}]interface{})
				newTranslatedIntegrator.FeatureConfigs = getFeatureConfigs(newTranslatedIntegrator.Type, featureConfigsData, featureModeOldSchemaTypeGrouping)
			}

			if featureConfigsExists && !integratorConfigsExists {
				newTranslatedIntegrator.Status = "connected"
			} else if len(newTranslatedIntegrator.IntegratorConfigs) > 0 {
				newTranslatedIntegrator.Status = "connected"
			} else {
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

func readAndUnmarshalyaml() (IntegrationStages, error) {

	var configs SSDIntegrations
	if err := yaml.Unmarshal([]byte(schemaYaml), &configs); err != nil {
		return nil, fmt.Errorf("error: Unmarshal: SSDIntegrations: %s", err.Error())
	}

	if len(configs.IntegrationData) == 0 {
		return nil, fmt.Errorf("error: no integrations found after unmarshal: %s", configs)
	}
	return configs.IntegrationData, nil
}
