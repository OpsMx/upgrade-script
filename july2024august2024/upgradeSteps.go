package july2024august2024

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToAugust2024(prodGraphUrl, prodToken, expDgraphUrl, restoreServiceUrl string, prodDgraphClient, expDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting performScanJiraDetailsTransition------------------")

	if err := performJiraDetailsTransition(prodDgraphClient, expDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToAugust2024: performJiraDetailsTransition: %s", err.Error())
	}

	if err := graphqlfunc.BackupAndRestoreDgraph(expDgraphUrl, restoreServiceUrl); err != nil {
		return fmt.Errorf("UpgradeToAugust2024: BackupAndRestoreDgraph: %s", err.Error())
	}

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.August2024Schema)); err != nil {
		return fmt.Errorf("UpgradeToAugust2024: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToAugust2024------------------")

	return nil
}
