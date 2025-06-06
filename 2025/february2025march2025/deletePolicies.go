package february2025march2025

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func DeletePolicies(prodDgraphClient graphql.Client) error {
	logger.Logger.Info("--------------Beginning to perform step: deletePolicies------------------")

	logger.Logger.Info("--------------starting step: GetPolicyEnforcement------------------")
	enfResp, err := QueryPolicyEnforcement(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("QueryPolicyEnforcement: error: %s", err.Error())
	}

	logger.Logger.Info("--------------starting step: DeletePolicyEnforcement------------------")
	for _, policyEnf := range enfResp.QueryPolicyEnforcement {
		if _, err := DeletePolicyEnforcement(context.Background(), prodDgraphClient, policyEnf.Id); err != nil {
			return fmt.Errorf("DeletePolicyEnforcement: id: %s error: %s", *policyEnf.Id, err.Error())
		}
	}

	logger.Logger.Info("--------------completed step: DeletePolicyEnforcement------------------")

	logger.Logger.Info("--------------starting step: DeletePolicyDefinition------------------")

	if _, err := DeletePolicyDefinition(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("DeletePolicyDefinition: error: %s", err.Error())
	}

	logger.Logger.Info("--------------completed step: DeletePolicyDefinition------------------")

	logger.Logger.Info("--------------Completed step: deletePolicies------------------")
	return nil
}
