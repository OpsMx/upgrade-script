package june2024v2july2024

import (
	"context"
	"encoding/json"
	"fmt"
	"upgradationScript/june2024v2july2024/july2024"
	"upgradationScript/june2024v2july2024/june2024v2"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func performIntegratorsTransition(prodDgraphClient, expDgraphClient graphql.Client) error {

	ctx := context.Background()

	existingFeatureModes, err := june2024v2.QueryFeatureMode(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: QueryFeatureMode: could'nt query old prod features to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Commencing feature mode transition iterations to complete %d -----------------", len(existingFeatureModes.QueryFeatureMode))

	featureModeIntegratorTypeGrouping := make(map[string][]*july2024.FeatureModeRef)
	if len(existingFeatureModes.QueryFeatureMode) > 0 {

		for _, eachFeatureMode := range existingFeatureModes.QueryFeatureMode {

			translatedScanName := getTranslatedScanName(eachFeatureMode.Scan)
			temp := july2024.FeatureModeRef{
				Key:       translatedScanName,
				Value:     getValue(translatedScanName),
				Category:  eachFeatureMode.Category,
				CreatedAt: eachFeatureMode.CreatedAt,
				UpdatedAt: eachFeatureMode.UpdatedAt,
			}

			if val, ok := featureModeIntegratorTypeGrouping[eachFeatureMode.Type]; ok {
				val = append(val, &temp)
				featureModeIntegratorTypeGrouping[eachFeatureMode.Type] = val
			} else {
				featureModeIntegratorTypeGrouping[eachFeatureMode.Type] = []*july2024.FeatureModeRef{&temp}
			}
		}
	}

	existingIntegrators, err := june2024v2.QueryExistingIntegrators(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: QueryExistingIntegrators: could'nt query old prod integrators to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Commencing integrators configs transition iterations to complete %d -----------------", len(existingIntegrators.QueryIntegrator))

	if len(existingIntegrators.QueryIntegrator) > 0 {

		integratorTypeGrouping := make(map[string]july2024.AddIntegratorInput)

		for iter, eachIntegrator := range existingIntegrators.QueryIntegrator {
			logger.Logger.Debug("---------------------------------------------")
			logger.Sl.Debugf("existing integrators Iteration %d to begin", iter)

			var existingIntegratorData map[string]string
			if err := json.Unmarshal([]byte(eachIntegrator.Credentials.Data), &existingIntegratorData); err != nil {
				logger.Sl.Errorf("error: performIntegratorsTransition: Unmarshal: %s for integrator type: %s", err.Error(), eachIntegrator.Type)
				continue
			}

			var configValues []*july2024.IntegratorKeyValuesRef
			for key, eachConfigData := range existingIntegratorData {
				if eachConfigData == "" {
					continue
				}
				encrypt := IsEncryptionRequired(key)
				configValues = append(configValues, &july2024.IntegratorKeyValuesRef{
					Key:     key,
					Value:   eachConfigData,
					Encrypt: &encrypt,
				})
			}

			configTemp := july2024.IntegratorConfigsRef{
				Name:    eachIntegrator.Name,
				Configs: configValues,
			}

			if val, ok := integratorTypeGrouping[eachIntegrator.Type]; ok {

				if supportMultipleInsertion(eachIntegrator.Type) {
					val.IntegratorConfigs = append(val.IntegratorConfigs, &configTemp)
					integratorTypeGrouping[eachIntegrator.Type] = val
				}

			} else {

				var currFeatureConfigs []*july2024.FeatureModeRef
				if val, ok := featureModeIntegratorTypeGrouping[eachIntegrator.Type]; ok {
					currFeatureConfigs = val
					delete(featureModeIntegratorTypeGrouping, eachIntegrator.Type)
				}

				integratorTypeGrouping[eachIntegrator.Type] = july2024.AddIntegratorInput{
					Organization: &july2024.OrganizationRef{
						Id: eachIntegrator.Organization.Id,
					},
					Type:              eachIntegrator.Type,
					Category:          eachIntegrator.Category,
					Status:            "disabled",
					CreatedAt:         eachIntegrator.CreatedAt,
					UpdatedAt:         eachIntegrator.UpdatedAt,
					IntegratorConfigs: []*july2024.IntegratorConfigsRef{&configTemp},
					FeatureConfigs:    currFeatureConfigs,
				}
			}
			logger.Sl.Debugf("existing integrators Iteration %d completed", iter)
		}

		var translatedIntegators []*july2024.AddIntegratorInput
		for _, val := range integratorTypeGrouping {
			translatedIntegators = append(translatedIntegators, &val)
		}

		logger.Sl.Debug("adding Integrators to the database")

		if _, err := july2024.AddIntegrator(ctx, expDgraphClient, translatedIntegators); err != nil {
			return fmt.Errorf("error: performIntegratorsTransition: AddIntegrator error: %s", err.Error())
		}
		logger.Sl.Debug("added Integrators to the database")

		logger.Logger.Info("------------Integrators upgrade complete-------------------------")
	}

	if len(existingFeatureModes.QueryFeatureMode) > 0 {
		logger.Sl.Debug("adding remaining Fetaure Mode to the database")

		var translatedFeatureModes []*july2024.AddFeatureModeInput
		for _, val := range featureModeIntegratorTypeGrouping {

			for _, eachFeatureMode := range val {
				temp := july2024.AddFeatureModeInput{
					Key:       eachFeatureMode.Key,
					Value:     eachFeatureMode.Value,
					Category:  eachFeatureMode.Category,
					CreatedAt: eachFeatureMode.CreatedAt,
					UpdatedAt: eachFeatureMode.UpdatedAt,
				}
				translatedFeatureModes = append(translatedFeatureModes, &temp)
			}
		}

		if _, err := july2024.AddFeatureMode(ctx, expDgraphClient, translatedFeatureModes); err != nil {
			return fmt.Errorf("error: performIntegratorsTransition: AddIntegrator error: %s", err.Error())
		}
		logger.Sl.Debug("added remaining Fetaure Mode to the database")

		logger.Logger.Info("------------Feature Mode upgrade complete-------------------------")
	}

	return nil
}
