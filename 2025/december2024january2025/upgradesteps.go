package december2024january2025

import (
	"context"
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToJanuary2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToJanuary2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.January2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToJanuary2025: UpdateSchema: %s", err.Error())
	}

	resp, err := GetGlobalOrgID(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: UpgradeToJanuary2025: GetGlobalOrgID: %s", err.Error())
	}

	if _, err := SetIntegratorConfigsOrgID(context.Background(), prodDgraphClient, resp.QueryOrganization[0].Id); err != nil {
		return fmt.Errorf("error: UpgradeToJanuary2025: SetIntegratorConfigsOrgID: %s", err.Error())
	}

	if _, err := SetDefaultValueOfHosting(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToJanuary2025: SetDefaultValueOfHosting: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToJanuary2025------------------")

	return nil
}
