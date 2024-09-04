package june2024v2july2024

import (
	"context"
	"encoding/json"
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

	vulnScanType := "trivy"
	var orgId string
	for _, eachFeatureMode := range existingFeatureModes.QueryFeatureMode {

		orgId = eachFeatureMode.Organization.Id

		if eachFeatureMode.Type == "kubescape" {
			logger.Sl.Debug("Skipping kubescape featconfigs as not needed in next release")
			// this has been shifted and isnt a part of integrator/feature table anymore
			// omitting to avoid unnecessary handling later
			continue
		}

		if val, ok := featureModeOldSchemaTypeGrouping[eachFeatureMode.Type]; ok {
			val = append(val, *eachFeatureMode)
			featureModeOldSchemaTypeGrouping[eachFeatureMode.Type] = val
		} else {
			featureModeOldSchemaTypeGrouping[eachFeatureMode.Type] = []june2024v2.QueryFeatureModeQueryFeatureMode{*eachFeatureMode}
		}

		if eachFeatureMode.Type == "grype" {
			vulnScanType = "grype"
		}
	}

	existingIntegrators, err := june2024v2.QueryExistingIntegrators(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: QueryExistingIntegrators: could'nt query old prod integrators to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("----------Number Of Existing integrators configs transition in old db %d --------------", len(existingIntegrators.QueryIntegrator))

	integratorOldSchemaTypeGrouping := make(map[string][]june2024v2.QueryExistingIntegratorsQueryIntegrator)

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
			newTranslatedIntegrator.Status = "disabled"

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

			_, featureConfigsExists := convMap["featureConfigs"]
			if featureConfigsExists {

				newTranslatedIntegrator.FeatureConfigs = getFeatureConfigs(newTranslatedIntegrator.Type, newTranslatedIntegrator.Category, featureModeOldSchemaTypeGrouping)

				if newTranslatedIntegrator.Type == "bitbucket" && len(newTranslatedIntegrator.IntegratorConfigs) > 0 {
					now := time.Now()

					addFeat := july2024.FeatureModeRef{
						Organization: &july2024.OrganizationRef{
							Id: orgId,
						},
						CreatedAt: &now,
						UpdatedAt: &now,
						Key:       "accessLevel",
						Category:  "sourcetool",
					}

					allData := integratorOldSchemaTypeGrouping["bitbucket"]
					for _, eachEntry := range allData {

						var existingIntegratorData map[string]string
						if err = json.Unmarshal([]byte(eachEntry.Credentials.Data), &existingIntegratorData); err != nil {
							err = fmt.Errorf("error: Unmarshal: %s for integrator data from old db: %s", err.Error(), eachEntry.Type)
							return err
						}

						for dataKey, eachParamEntry := range existingIntegratorData {

							if dataKey != "accessLevel" {
								continue
							}

							if eachParamEntry == "workspace" {
								addFeat.Value = "Workspace"
							} else if eachParamEntry == "project" {
								addFeat.Value = "Project"
							} else {
								addFeat.Value = "Repository"
							}
						}
					}

					newTranslatedIntegrator.FeatureConfigs = append(newTranslatedIntegrator.FeatureConfigs, &addFeat)

				}

				if newTranslatedIntegrator.Type == "trivy" && vulnScanType == "grype" {
					now := time.Now()

					addFeat := july2024.FeatureModeRef{
						Organization: &july2024.OrganizationRef{
							Id: orgId,
						},
						CreatedAt: &now,
						UpdatedAt: &now,
						Key:       "vulnerabilityscan",
						Value:     "inactive",
						Category:  "scanningtool",
					}

					newTranslatedIntegrator.FeatureConfigs = append(newTranslatedIntegrator.FeatureConfigs, &addFeat)

				}

			}

			if (featureConfigsExists && !integratorConfigsExists) || len(newTranslatedIntegrator.IntegratorConfigs) > 0 {
				newTranslatedIntegrator.Status = "connected"
			}

			if len(newTranslatedIntegrator.IntegratorConfigs) == 0 && len(newTranslatedIntegrator.FeatureConfigs) == 0 {
				// dont add if nothing api svc will create it
				// example case grype
				// or any other integrator type of no featsConfigs like github not added in old db
				continue
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
	if err := yaml.Unmarshal([]byte(july2024.SchemaYaml), &configs); err != nil {
		return nil, fmt.Errorf("error: Unmarshal: SSDIntegrations: %s", err.Error())
	}

	if len(configs.IntegrationData) == 0 {
		return nil, fmt.Errorf("error: invalid schema yaml for integrator July2024")
	}
	return configs.IntegrationData, nil
}
