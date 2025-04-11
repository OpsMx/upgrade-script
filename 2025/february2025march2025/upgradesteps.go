package february2025march2025

import (
	"context"
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

	if err := AddSbomToolToArtifactRunHistory(prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToMarch2025: AddSbomToolToArtifactRunHistory: %s", err.Error())
	}

	if err := DeletePolicies(prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToMarch2025: DeletePolicies: %s", err.Error())
	}

	if _, err := UpdateBlockedApplicationDeployment(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToMarch2025: UpdateBlockedApplicationDeploymentResponse: %s", err.Error())
	}

	if _, err := UpdateNonBlockedApplicationDeployment(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToMarch2025: UpdateBlockedApplicationDeploymentResponse: %s", err.Error())
	}
	logger.Logger.Info("--------------Completed UpgradeToMarch2025------------------")

	return nil
}
