package november2024december2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

type FeatureModeDetails struct {
	OrgID         string
	FeatureValues []FeatureValue
}

type FeatureValue struct {
	Key   string
	Value string
}

type IntegratorKey struct {
	IntegratorType string
	IntegratorID   string
}

func migrateFeatureToConfigKeyValues(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----migrating Feature Node to Integrator Config Key Values--------")

	ctx := context.Background()

	res, err := FetchFeatureConfigsWithIntegratorConfigID(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in getting feature configs with integrator config id: %s", err.Error())
	}

	if len(res.QueryFeatureMode) == 0 {
		return fmt.Errorf("ro record for feature mode")
	}

	detailsToMigrate := make(map[string]FeatureModeDetails)
	featureMappingByIntegrator := make(map[IntegratorKey]string)

	for _, feature := range res.QueryFeatureMode {

		integratorConfigID, err := getIntegratorConfigID(ctx, gqlClient, feature, featureMappingByIntegrator)
		if err != nil {
			return fmt.Errorf("error in getting integrator config id to populate config keys: %s", err.Error())
		}

		if _, ok := detailsToMigrate[integratorConfigID]; !ok {
			detailsToMigrate[integratorConfigID] = FeatureModeDetails{
				OrgID: feature.Organization.Id,
				FeatureValues: []FeatureValue{
					{
						Key:   feature.Key,
						Value: feature.Value,
					},
				},
			}
		} else {
			temp := detailsToMigrate[integratorConfigID]
			temp.FeatureValues = AppendIfNotPresent(temp.FeatureValues, FeatureValue{
				Key:   feature.Key,
				Value: feature.Value,
			})
			detailsToMigrate[integratorConfigID] = temp
		}
	}

	True, False := true, false

	for key, val := range detailsToMigrate {

		keyValueToSet := make([]*IntegratorKeyValuesRef, 0, len(val.FeatureValues))

		for _, eachFeatureValue := range val.FeatureValues {
			keyValueToSet = append(keyValueToSet, &IntegratorKeyValuesRef{
				Feat:    &True,
				Key:     eachFeatureValue.Key,
				Value:   eachFeatureValue.Value,
				Encrypt: &False,
			})
		}

		_, err := SetIntegratorConfigStatusAndUpdateKeyValues(ctx, gqlClient, &key, val.OrgID, keyValueToSet)
		if err != nil {
			return fmt.Errorf("error in setting integrator config and updating key values: %s", err.Error())
		}
	}

	logger.Sl.Debugf("-----migrated Feature Node to Integrator Config Key Values--------")
	return nil
}

func getIntegratorConfigID(ctx context.Context, gqlClient graphql.Client, feature *FetchFeatureConfigsWithIntegratorConfigIDQueryFeatureMode,
	featureMappingByIntegrator map[IntegratorKey]string) (string, error) {

	if len(feature.Integrator.IntegratorConfigs) != 0 {
		return *feature.Integrator.IntegratorConfigs[0].Id, nil
	}

	key := IntegratorKey{
		IntegratorType: feature.Integrator.Type,
		IntegratorID:   feature.Integrator.Id,
	}

	if val, ok := featureMappingByIntegrator[key]; ok {
		return val, nil
	}

	res, err := AddIntegratorConfigs(ctx, gqlClient, &AddIntegratorConfigsInput{
		Name:   feature.Integrator.Type,
		Status: "active",
		Organization: &OrganizationRef{
			Id: feature.Organization.Id,
		},
		Integrator: &IntegratorRef{
			Id: feature.Integrator.Id,
		},
	})

	if err != nil {
		return "", fmt.Errorf("error in adding integratorConfig for integrator type: %s  %s", feature.Integrator.Type, err.Error())
	}

	if res.AddIntegratorConfigs == nil || len(res.AddIntegratorConfigs.IntegratorConfigs) == 0 {
		return "", fmt.Errorf("no records found after adding integrator config for integrator id %s and type %s", feature.Integrator.Id, feature.Integrator.Type)
	}

	integratorConfigID := *res.AddIntegratorConfigs.IntegratorConfigs[0].Id
	featureMappingByIntegrator[key] = integratorConfigID

	return integratorConfigID, nil
}
