package december2024january2025

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToJanuary2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToJanuary2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.January2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToDecember2024: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToJanuary2025------------------")

	return nil
}
