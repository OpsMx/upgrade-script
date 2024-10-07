package august2024v2september2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func populatePolicyEvalDataForVulnerabilities(prodDgraphClient graphql.Client) error {

	logger.Sl.Debugf("-----populating PolicyEvalData For Vulnerabilities--------")

	allVulns, err := GetAllVulnerabilities(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("GetAllVulnerabilities: err: %s", err.Error())
	}

	logger.Sl.Debugf("Total iteration", len(allVulns.QueryVulnerability))

	for _, vuln := range allVulns.QueryVulnerability {
		securityIssues, err := SecurityIssueOfVuln(context.Background(), prodDgraphClient, fmt.Sprintf("/%s/i", vuln.Parent))
		if err != nil {
			return fmt.Errorf("SecurityIssueOfVuln: vuln:%s err: %s", vuln.Parent, err.Error())
		}

		var allData []*AddPolicyEvaluationDataInput
		for _, securityIssue := range securityIssues.QuerySecurityIssue {
			for _, runHistory := range securityIssue.Affects {

				allData = append(allData, &AddPolicyEvaluationDataInput{
					DataType: "vulnnode",
					Affects: &RunHistoryRef{
						Id:              runHistory.Id,
						Pass:            runHistory.Pass,
						ScheduledPolicy: runHistory.ScheduledPolicy,
					},
					VulnNode: &VulnerabilityRef{
						Id:      vuln.Id,
						Ratings: vuln.Ratings,
					},
				})
			}
		}

		if allData == nil {
			continue
		}

		if _, err := AddPolicyEvaluationData(context.Background(), prodDgraphClient, allData); err != nil {
			return fmt.Errorf("AddPolicyEvaluationData: for vuln:%s err: %s", vuln.Parent, err.Error())
		}

	}

	logger.Sl.Debugf("-----populated PolicyEvalData For Vulnerabilities--------")

	return nil

}
