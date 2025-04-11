package february2025march2025

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToMarch2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToMarch2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.March2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToMarch2025: UpdateSchema: %s", err.Error())
	}

	if err := AddDeploymentDetailsToRunHistory(prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToMarch2025: AddDeploymentDetailsToRunHistory: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToMarch2025------------------")

	return nil
}
