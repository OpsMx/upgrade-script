package august2024v2september2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func migratePolicyEnfToSecurityIssues(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----migrating PolicyEnf To SecurityIssues--------")

	ctx := context.Background()

	resp, err := GetPolicyEnfIdFromRunHistory(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in getting policy enforcemnet id from run history: %s", err.Error())
	}

	if resp == nil {
		logger.Sl.Debugf("No record for policy enforcment ids within run history found in db")
		return nil
	}

	logger.Sl.Debugf("The total number of security issue records to link with the policy enforcement record:", len(resp.QuerySecurityIssue))

	type scanDataUpdate struct {
		securityIssueId   string
		policyEnformentId string
	}

	scanDataUpdates := make([]scanDataUpdate, 0, len(resp.QuerySecurityIssue))

	for _, eachSecurityIssue := range resp.QuerySecurityIssue {
		if eachSecurityIssue.Id != nil && eachSecurityIssue.Affects != nil {
			scanDataUpdates = append(scanDataUpdates, scanDataUpdate{
				securityIssueId:   *eachSecurityIssue.Id,
				policyEnformentId: *eachSecurityIssue.Affects[0].PolicyEnforcements.Id,
			})
		}
	}

	for _, value := range scanDataUpdates {
		if _, err := UpdatePolicyEnfInSecurityIssue(ctx, gqlClient, &value.securityIssueId, &value.policyEnformentId); err != nil {
			return fmt.Errorf("error in updating the policy enforcement id %s in security issue id %s : %s", value.policyEnformentId, value.securityIssueId, err.Error())
		}
	}

	logger.Sl.Debugf("-----migrated PolicyEnf To SecurityIssues--------")

	return nil
}

func setForceApplyForGraphQL(gqlClient graphql.Client) error {

	ctx := context.Background()

	logger.Sl.Debugf("-----Updating ForcePolicy For Graphql Tool--------")

	if _, err := UpdateForcePolicyForGraphqlTool(ctx, gqlClient); err != nil {
		return fmt.Errorf("error while updating forecpolicy field in policy enforcment for graphql tool: %s", err.Error())
	}

	logger.Sl.Debugf("-----Updated ForcePolicy For Graphql Tool--------")
	return nil

}
