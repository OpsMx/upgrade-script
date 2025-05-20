package march2025april2025

import (
	"context"
	"encoding/json"
	"fmt"
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

func SyncPoliciesWRepo(client graphql.Client) error {
	policyIdsMap := make(map[string]int)
	if err := json.Unmarshal([]byte(policyIds), &policyIdsMap); err != nil {
		return fmt.Errorf("SyncPoliciesWRepo: json.Unmarshal error: %s", err.Error())
	}

	var policiesToFix []PolicyToFix
	policyNames := []string{}
	policiesDelete := []string{}

	for policyName, ID := range policyIdsMap {
		policyNames = append(policyNames, policyName)
		policyResp, err := GetPolicyEnfIDOfPolicyDef(context.Background(), client, policyName)
		if err != nil {
			return fmt.Errorf("SyncPoliciesWRepo: policyName %s error: %s", policyName, err.Error())
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

	resp, err := ExtraPolicies(context.Background(), client, policyNames)
	if err != nil {
		return fmt.Errorf("SyncPoliciesWRepo: ExtraPolicies: error: %s", err.Error())
	}

	for _, policy := range resp.QueryPolicyDefinition {
		policiesDelete = append(policiesDelete, policy.Id)
	}

	if _, err = DeletePolicyDefinition(context.Background(), client, policiesDelete); err != nil {
		return fmt.Errorf("SyncPoliciesWRepo: DeletePolicyDefinition: error: %s", err.Error())
	}

	for _, policy := range policiesToFix {
		if _, err := AddPolicyDefinition(context.Background(), client, &AddPolicyDefinitionInput{
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

		if _, err := UpdatePolicyEnforcement(context.Background(), client, policy.PolicyEnfIDs, policy.PolicyIDExpected); err != nil {
			return fmt.Errorf("SyncPoliciesWRepo: error UpdatePolicyEnforcement: %s", err.Error())
		}
	}

	return nil
}
