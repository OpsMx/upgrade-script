package march2025april2025

import (
	"context"
	"encoding/json"
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

type PolicyToFix struct {
	PolicyName       string
	PolicyIDExpected string
	PolicyIDGot      string
	PolicyEnfIDs     []*string
	PolicyDef        *GetPolicyEnfIDOfPolicyDefQueryPolicyEnforcementPolicyPolicyDefinition
}

func SyncPoliciesWRepo(prodGraphUrl, prodToken string) error {
	policyIdsMap := make(map[string]int)
	if err := json.Unmarshal([]byte(policyIds), &policyIdsMap); err != nil {
		return fmt.Errorf("SyncPoliciesWRepo: json.Unmarshal error: %s", err.Error())
	}

	var policiesToFix []PolicyToFix
	policyNames := []string{}
	policiesDelete := []string{}

	for policyName, ID := range policyIdsMap {
		client := graphqlfunc.NewClient(prodGraphUrl, prodToken)
		policyNames = append(policyNames, policyName)

		var policyResp *GetPolicyEnfIDOfPolicyDefResponse
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			var err error
			policyResp, err = GetPolicyEnfIDOfPolicyDef(ctx, client, policyName)
			if err != nil {
				return fmt.Errorf("SyncPoliciesWRepo: policyName %s error: %s", policyName, err.Error())
			}
			return nil
		}); err != nil {
			return err
		}

		if len(policyResp.QueryPolicyEnforcement) == 0 {
			logger.Logger.Sugar().Debugf("PolicyName %s doesnt exist will be added by api-svc", policyName)
			continue
		}
		check := PolicyToFix{
			PolicyName:       policyName,
			PolicyIDExpected: fmt.Sprint(ID),
			PolicyIDGot:      policyResp.QueryPolicyEnforcement[0].Policy.Id,
			PolicyDef:        policyResp.QueryPolicyEnforcement[0].Policy,
		}

		if check.PolicyIDExpected != check.PolicyIDGot {
			policiesDelete = append(policiesDelete, check.PolicyIDGot)
			for _, enf := range policyResp.QueryPolicyEnforcement {
				check.PolicyEnfIDs = append(check.PolicyEnfIDs, enf.Id)
			}
			policiesToFix = append(policiesToFix, check)
		}
	}

	client := graphqlfunc.NewClient(prodGraphUrl, prodToken)

	var resp *ExtraPoliciesResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		resp, err = ExtraPolicies(ctx, client, policyNames)
		if err != nil {
			return fmt.Errorf("SyncPoliciesWRepo: ExtraPolicies: error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	for _, policy := range resp.QueryPolicyDefinition {
		policiesDelete = append(policiesDelete, policy.Id)
	}

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		// Call the deletion function for the current batch
		if _, err := DeletePolicyDefinition(ctx, client, policiesDelete); err != nil {
			return fmt.Errorf("SyncPoliciesWRepo: DeletePolicyDefinition: error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	for _, policy := range policiesToFix {
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			// Call the deletion function for the current batch
			if _, err := AddPolicyDefinition(ctx, client, &AddPolicyDefinitionInput{
				Id: policy.PolicyIDExpected,
				OwnerOrg: &OrganizationRef{
					Id: policy.PolicyDef.OwnerOrg.Id,
				},
				CreatedAt:       policy.PolicyDef.CreatedAt,
				UpdatedAt:       policy.PolicyDef.UpdatedAt,
				PolicyName:      policy.PolicyDef.PolicyName,
				Category:        policy.PolicyDef.Category,
				Stage:           policy.PolicyDef.Stage,
				Description:     policy.PolicyDef.Description,
				ScheduledPolicy: policy.PolicyDef.ScheduledPolicy,
				Script:          policy.PolicyDef.Script,
				Variables:       policy.PolicyDef.Variables,
				ConditionName:   policy.PolicyDef.ConditionName,
				Suggestion:      policy.PolicyDef.Suggestion,
			}); err != nil {
				return fmt.Errorf("SyncPoliciesWRepo: error AddPolicyDefinition: %s", err.Error())
			}
			return nil
		}); err != nil {
			return err
		}

		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			// Call the deletion function for the current batch
			if _, err := UpdatePolicyEnforcement(ctx, client, policy.PolicyEnfIDs, policy.PolicyIDExpected); err != nil {
				return fmt.Errorf("SyncPoliciesWRepo: error UpdatePolicyEnforcement: %s", err.Error())
			}
			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}
