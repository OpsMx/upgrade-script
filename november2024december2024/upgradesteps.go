package november2024december2024

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToDecember2024(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToDecember2024------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(translationSchema)); err != nil {
		return fmt.Errorf("error: UpgradeToDecember2024: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Added Dec Translate Schema------------------")

	if err := migrateFeatureToConfigKeyValues(prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToDecember2024: migrateFeatureToConfigKeyValues: %s", err.Error())
	}

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.December2024Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToDecember2024: UpdateSchema: %s", err.Error())
	}

	if err := updateArtifactTypeForPlugin(prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToDecember2024: updateArtifactTypeForPlugin: %s", err.Error())
	}

	if err := updateIntegratorMetadata(prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToDecember2024: updateIntegratorMetadata: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToDecember2024------------------")

	return nil
}
