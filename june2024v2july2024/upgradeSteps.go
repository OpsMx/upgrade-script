package june2024v2july2024

import (
	"fmt"

	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToJuly2024(prodGraphUrl, prodToken, expDgraphUrl, restoreServiceUrl string, prodDgraphClient, expDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToJuly2024------------------")

	if err := performScanFilesTransition(prodDgraphClient, expDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToJuly2024: %s", err.Error())
	}

	if err := graphqlfunc.BackupAndRestoreDgraph(expDgraphUrl, restoreServiceUrl); err != nil {
		return fmt.Errorf("UpgradeToJuly2024: BackupAndRestoreDgraph: %s", err.Error())
	}

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.July2024Schema)); err != nil {
		return fmt.Errorf("UpgradeToJuly2024: UpdateSchema: %s", err.Error())
	}

	if err := populateSeverityNumber(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToJuly2024: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToJuly2024------------------")

	return nil
}
