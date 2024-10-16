package netradyne

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToNetradyne(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToNetradyne------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.NetradyneSchema)); err != nil {
		return fmt.Errorf("UpgradeToNetradyne: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToNetradyne------------------")

	return nil
}
