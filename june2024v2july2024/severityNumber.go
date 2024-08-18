package june2024v2july2024

import (
	"context"
	"fmt"
	"upgradationScript/june2024v2july2024/july2024"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func populateSeverityNumber(prodDgraphClient graphql.Client) error {
	ctx := context.Background()

	logger.Logger.Debug("--------------Populating Severity Number In Severity Issues-----------------")

	allSecurityIssues, err := july2024.GetSeverityFromSecurityIssue(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("populateSeverityNumber: could'nt query severity issues error: %s", err.Error())
	}

	securityIssuesSeverityWiseMap := make(map[int][]*string)

	for _, eachSecurityIssue := range allSecurityIssues.QuerySecurityIssue {
		logger.Logger.Debug("---------------------------------------------")
		logger.Sl.Debugf("Severity Number to be populated for id %v", eachSecurityIssue.Id)

		switch eachSecurityIssue.Severity {
		case july2024.SeverityCritical:
			securityIssuesSeverityWiseMap[0] = append(securityIssuesSeverityWiseMap[0], eachSecurityIssue.Id)
		case july2024.SeverityHigh:
			securityIssuesSeverityWiseMap[1] = append(securityIssuesSeverityWiseMap[1], eachSecurityIssue.Id)
		case july2024.SeverityMedium:
			securityIssuesSeverityWiseMap[2] = append(securityIssuesSeverityWiseMap[2], eachSecurityIssue.Id)
		default:
			securityIssuesSeverityWiseMap[3] = append(securityIssuesSeverityWiseMap[3], eachSecurityIssue.Id)
		}
	}

	for key, val := range securityIssuesSeverityWiseMap {

		if _, err := july2024.UpdateSeverityIntInSecurityIssues(ctx, prodDgraphClient, val, &key); err != nil {
			return fmt.Errorf("populateSeverityNumber: UpdateSeverityIntInSecurityIssues error: %s", err.Error())
		}
	}

	logger.Logger.Debug("---------------------------------------------")

	logger.Logger.Debug("--------------Completed Severity Number Transition-----------------")

	return nil
}
