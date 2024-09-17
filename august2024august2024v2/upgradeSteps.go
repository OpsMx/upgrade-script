package august2024august2024v2

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToAugust2024v2(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting Artifact Score Calculation------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.August2024Version2)); err != nil {
		return fmt.Errorf("UpgradeToAugust2024v2: UpdateSchema: %s", err.Error())
	}

	if err := calculateScoring(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToAugust2024v2: calculateScoring: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToAugust2024v2------------------")

	return nil
}
