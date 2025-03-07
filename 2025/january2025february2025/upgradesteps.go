package january2025february2025

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToFebruary2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToFebruary2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.February2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToFebruary2025: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToFebruary2025------------------")

	return nil
}
