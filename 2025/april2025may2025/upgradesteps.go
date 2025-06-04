package april2025may2025

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToMay2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToMay2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.May2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToMay2025: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToMay2025------------------")

	return nil
}
