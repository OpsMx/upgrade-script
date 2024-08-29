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

	existingIntegrators, err := june2024v2.QueryExistingIntegrators(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performIntegratorsTransition: QueryExistingIntegrators: could'nt query old prod integrators to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Commencing scanned files transition iterations to complete %d -----------------", len(existingIntegrators.QueryIntegrator))

	if len(existingIntegrators.QueryIntegrator) == 0 {
		logger.Sl.Debugf("No Integrators Found while running performIntegratorsTransition")
	}

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

			val.IntegratorConfigs = append(val.IntegratorConfigs, &configTemp)
			integratorTypeGrouping[eachIntegrator.Type] = val

		} else {

			integratorTypeGrouping[eachIntegrator.Type] = july2024.AddIntegratorInput{
				Organization: &july2024.OrganizationRef{
					Id: eachIntegrator.Organization.Id,
				},
				Type:              eachIntegrator.Type,
				Category:          eachIntegrator.Category,
				Status:            "not-connected",
				IntegratorConfigs: []*july2024.IntegratorConfigsRef{&configTemp},
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

	return nil
}

func IsEncryptionRequired(configKey string) (isRequired bool) {

	switch configKey {
	case "token":
		isRequired = true
	case "password":
		isRequired = true
	case "awsAccessKey":
		isRequired = true
	case "awsSecretKey":
		isRequired = true
	case "key":
		isRequired = true
	default:
		isRequired = false
	}
	return isRequired
}
