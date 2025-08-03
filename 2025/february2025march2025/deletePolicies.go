package february2025march2025

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func DeletePolicies(prodGraphUrl, prodToken string) error {
	logger.Logger.Info("--------------Beginning to perform step: deletePolicies------------------")

	logger.Logger.Info("--------------starting step: GetPolicyEnforcement------------------")
	var enfResp *QueryPolicyEnforcementResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		enfResp, err = QueryPolicyEnforcement(context.Background(), gqlClient)
		if err != nil {
			return fmt.Errorf("QueryPolicyEnforcement: error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	logger.Logger.Info("--------------starting step: DeletePolicyEnforcement------------------")
	for _, policyEnf := range enfResp.QueryPolicyEnforcement {
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			if _, err := DeletePolicyEnforcement(context.Background(), gqlClient, policyEnf.Id); err != nil {
				return fmt.Errorf("DeletePolicyEnforcement: id: %s error: %s", *policyEnf.Id, err.Error())
			}
			return nil
		}); err != nil {
			return err
		}

	}

	logger.Logger.Info("--------------completed step: DeletePolicyEnforcement------------------")

	logger.Logger.Info("--------------starting step: DeletePolicyDefinition------------------")

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		if _, err := DeletePolicyDefinition(context.Background(), gqlClient); err != nil {
			return fmt.Errorf("DeletePolicyDefinition: error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	logger.Logger.Info("--------------completed step: DeletePolicyDefinition------------------")

	logger.Logger.Info("--------------Completed step: deletePolicies------------------")
	return nil
}
