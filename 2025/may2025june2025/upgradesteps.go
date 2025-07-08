package may2025june2025

import (
	"context"
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToMay2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToJune2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.May2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToJune2025: UpdateSchema: %s", err.Error())
	}

	if _, err := SetProjectRiskAsCompleted(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToJune2025: SetProjectRiskAsCompleted: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToJune2025------------------")

	return nil
}
