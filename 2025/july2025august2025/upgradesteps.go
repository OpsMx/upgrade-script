package july2025august2025

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToAugust2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToAugust2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.August2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToAugust2025: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToAugust2025------------------")

	return nil
}
