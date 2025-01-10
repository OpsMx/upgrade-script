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

func migrateFeatureToConfigKeyValues(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----migrating Feature Node to Integrator Config Key Values--------")

	ctx := context.Background()

	res, err := FetchFeatureConfigsWithIntegratorConfigID(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in getting  id: %s", err.Error())
	}

	if len(res.QueryFeatureMode) == 0 {
		logger.Sl.Debugf("No record for feature mode")
		return nil
	}

	detailsToMigrate := make(map[string]FeatureModeDetails)

	for _, feature := range res.QueryFeatureMode {

		if len(feature.Integrator.IntegratorConfigs) != 0 {
			integratorID := *feature.Integrator.IntegratorConfigs[0].Id
			if _, ok := detailsToMigrate[integratorID]; !ok {
				detailsToMigrate[integratorID] = FeatureModeDetails{
					OrgID: feature.Organization.Id,
					FeatureValues: []FeatureValue{
						{
							Key:   feature.Key,
							Value: feature.Value,
						},
					},
				}
			} else {
				temp := detailsToMigrate[integratorID]
				temp.FeatureValues = AppendIfNotPresent(temp.FeatureValues, FeatureValue{
					Key:   feature.Key,
					Value: feature.Value,
				})
				detailsToMigrate[integratorID] = temp
			}

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
