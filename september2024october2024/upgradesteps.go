package september2024october2024

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToOctober2024(prodGraphUrl, prodToken, restoreServiceUrl string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToOctober2024------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(translationSchema)); err != nil {
		return fmt.Errorf("UpgradeToOctober2024: UpdateSchema: %s", err.Error())
	}

	if err := migrateBuildToSourceNode(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: migrateBuildToSourceNode: %s", err.Error())
	}

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.October2024Schema)); err != nil {
		return fmt.Errorf("UpgradeToOctober2024: UpdateSchema: %s", err.Error())
	}

	if restoreServiceUrl != "" {
		if err := graphqlfunc.BackupAndRestoreDgraph(prodGraphUrl, restoreServiceUrl); err != nil {
			return fmt.Errorf("UpgradeToOctober2024: BackupAndRestoreDgraph: %s", err.Error())
		}
	}

	logger.Logger.Info("--------------Completed UpgradeToOctober2024------------------")

	return nil
}
