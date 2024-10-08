package august2024v2september2024

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToSeptember2024(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToSeptember2024------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.September2024Schema)); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: UpdateSchema: %s", err.Error())
	}

	if err := updateVulnerabilityRatingsAndPriorityNum(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: updateVulnerabilityRatingsAndPriorityNum: %s", err.Error())
	}

	if err := setForceApplyForGraphQL(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: setForceApplyForGraphQL: %s", err.Error())
	}

	if err := ingestArtifactNameTag(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: ingestArtifactNameTag: %s", err.Error())
	}

	if err := migratePolicyEnfToSecurityIssues(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: migratePolicyEnfToSecurityIssues: %s", err.Error())
	}

	if err := populateBuildDetailsInArtifact(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: populateBuildDetailsInArtifact: %s", err.Error())
	}

	if err := populatePolicyEvalDataForVulnerabilities(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: populatePolicyEvalDataForVulnerabilities: %s", err.Error())
	}

	if err := setSummaryNodeForSecurityIssue(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToSeptember2024: setSummaryNodeForSecurityIssue: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToSeptember2024------------------")

	return nil
}
