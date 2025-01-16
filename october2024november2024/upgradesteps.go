package october2024november2024

import (
	"context"
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToNovember2024(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToNovember2024------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.November2024Schema)); err != nil {
		return fmt.Errorf("UpgradeToNovember2024: UpdateSchema: %s", err.Error())
	}

	if _, err := defaultVulnrichmentParams(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToNovember2024: defaultVulnrichmentParams: error:%s ", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToNovember2024------------------")
	return nil
}
