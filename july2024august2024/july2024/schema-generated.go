// Code generated by github.com/Khan/genqlient, DO NOT EDIT.

package july2024

import (
	"context"

	"github.com/Khan/genqlient/graphql"
)

// GetAttachedJiraUrlQueryRunHistory includes the requested fields of the GraphQL type RunHistory.
type GetAttachedJiraUrlQueryRunHistory struct {
	Id                 *string                                                               `json:"id"`
	JiraUrl            string                                                                `json:"JiraUrl"`
	PolicyEnforcements *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcement `json:"policyEnforcements"`
}

// GetId returns GetAttachedJiraUrlQueryRunHistory.Id, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlQueryRunHistory) GetId() *string { return v.Id }

// GetJiraUrl returns GetAttachedJiraUrlQueryRunHistory.JiraUrl, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlQueryRunHistory) GetJiraUrl() string { return v.JiraUrl }

// GetPolicyEnforcements returns GetAttachedJiraUrlQueryRunHistory.PolicyEnforcements, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlQueryRunHistory) GetPolicyEnforcements() *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcement {
	return v.PolicyEnforcements
}

// GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcement includes the requested fields of the GraphQL type PolicyEnforcement.
type GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcement struct {
	EnforcedOrg *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization `json:"enforcedOrg"`
}

// GetEnforcedOrg returns GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcement.EnforcedOrg, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcement) GetEnforcedOrg() *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization {
	return v.EnforcedOrg
}

// GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization includes the requested fields of the GraphQL type Organization.
type GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization struct {
	// id is randomly assigned
	Id   string `json:"id"`
	Name string `json:"name"`
}

// GetId returns GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization.Id, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization) GetId() string {
	return v.Id
}

// GetName returns GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization.Name, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlQueryRunHistoryPolicyEnforcementsPolicyEnforcementEnforcedOrgOrganization) GetName() string {
	return v.Name
}

// GetAttachedJiraUrlResponse is returned by GetAttachedJiraUrl on success.
type GetAttachedJiraUrlResponse struct {
	QueryRunHistory []*GetAttachedJiraUrlQueryRunHistory `json:"queryRunHistory"`
}

// GetQueryRunHistory returns GetAttachedJiraUrlResponse.QueryRunHistory, and is useful for accessing the field via an interface.
func (v *GetAttachedJiraUrlResponse) GetQueryRunHistory() []*GetAttachedJiraUrlQueryRunHistory {
	return v.QueryRunHistory
}

// QueryIntegratorsForOrgByTypeIfConnectedQueryOrganization includes the requested fields of the GraphQL type Organization.
type QueryIntegratorsForOrgByTypeIfConnectedQueryOrganization struct {
	Integrators []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator `json:"integrators"`
}

// GetIntegrators returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganization.Integrators, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganization) GetIntegrators() []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator {
	return v.Integrators
}

// QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator includes the requested fields of the GraphQL type Integrator.
type QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator struct {
	Type              string                                                                                                    `json:"type"`
	Category          string                                                                                                    `json:"category"`
	IntegratorConfigs []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs         `json:"integratorConfigs"`
	FeatureConfigs    []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode `json:"featureConfigs"`
}

// GetType returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator.Type, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator) GetType() string {
	return v.Type
}

// GetCategory returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator.Category, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator) GetCategory() string {
	return v.Category
}

// GetIntegratorConfigs returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator.IntegratorConfigs, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator) GetIntegratorConfigs() []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs {
	return v.IntegratorConfigs
}

// GetFeatureConfigs returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator.FeatureConfigs, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegrator) GetFeatureConfigs() []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode {
	return v.FeatureConfigs
}

// QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode includes the requested fields of the GraphQL type FeatureMode.
type QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// GetKey returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode.Key, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode) GetKey() string {
	return v.Key
}

// GetValue returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode.Value, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorFeatureConfigsFeatureMode) GetValue() string {
	return v.Value
}

// QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs includes the requested fields of the GraphQL type IntegratorConfigs.
type QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs struct {
	Name    string                                                                                                                      `json:"name"`
	Configs []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues `json:"configs"`
}

// GetName returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs.Name, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs) GetName() string {
	return v.Name
}

// GetConfigs returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs.Configs, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigs) GetConfigs() []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues {
	return v.Configs
}

// QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues includes the requested fields of the GraphQL type IntegratorKeyValues.
type QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Encrypt *bool  `json:"encrypt"`
}

// GetKey returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues.Key, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues) GetKey() string {
	return v.Key
}

// GetValue returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues.Value, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues) GetValue() string {
	return v.Value
}

// GetEncrypt returns QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues.Encrypt, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedQueryOrganizationIntegratorsIntegratorIntegratorConfigsConfigsIntegratorKeyValues) GetEncrypt() *bool {
	return v.Encrypt
}

// QueryIntegratorsForOrgByTypeIfConnectedResponse is returned by QueryIntegratorsForOrgByTypeIfConnected on success.
type QueryIntegratorsForOrgByTypeIfConnectedResponse struct {
	QueryOrganization []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganization `json:"queryOrganization"`
}

// GetQueryOrganization returns QueryIntegratorsForOrgByTypeIfConnectedResponse.QueryOrganization, and is useful for accessing the field via an interface.
func (v *QueryIntegratorsForOrgByTypeIfConnectedResponse) GetQueryOrganization() []*QueryIntegratorsForOrgByTypeIfConnectedQueryOrganization {
	return v.QueryOrganization
}

// __QueryIntegratorsForOrgByTypeIfConnectedInput is used internally by genqlient
type __QueryIntegratorsForOrgByTypeIfConnectedInput struct {
	Org            string   `json:"org"`
	Typefilter     string   `json:"typefilter"`
	IntegratorName []string `json:"integratorName"`
}

// GetOrg returns __QueryIntegratorsForOrgByTypeIfConnectedInput.Org, and is useful for accessing the field via an interface.
func (v *__QueryIntegratorsForOrgByTypeIfConnectedInput) GetOrg() string { return v.Org }

// GetTypefilter returns __QueryIntegratorsForOrgByTypeIfConnectedInput.Typefilter, and is useful for accessing the field via an interface.
func (v *__QueryIntegratorsForOrgByTypeIfConnectedInput) GetTypefilter() string { return v.Typefilter }

// GetIntegratorName returns __QueryIntegratorsForOrgByTypeIfConnectedInput.IntegratorName, and is useful for accessing the field via an interface.
func (v *__QueryIntegratorsForOrgByTypeIfConnectedInput) GetIntegratorName() []string {
	return v.IntegratorName
}

// The query or mutation executed by GetAttachedJiraUrl.
const GetAttachedJiraUrl_Operation = `
query GetAttachedJiraUrl {
	queryRunHistory @cascade {
		id
		JiraUrl
		policyEnforcements {
			enforcedOrg {
				id
				name
			}
		}
	}
}
`

func GetAttachedJiraUrl(
	ctx_ context.Context,
	client_ graphql.Client,
) (*GetAttachedJiraUrlResponse, error) {
	req_ := &graphql.Request{
		OpName: "GetAttachedJiraUrl",
		Query:  GetAttachedJiraUrl_Operation,
	}
	var err_ error

	var data_ GetAttachedJiraUrlResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by QueryIntegratorsForOrgByTypeIfConnected.
const QueryIntegratorsForOrgByTypeIfConnected_Operation = `
query QueryIntegratorsForOrgByTypeIfConnected ($org: String!, $typefilter: String!, $integratorName: [String!]) {
	queryOrganization(filter: {name:{eq:$org}}) @cascade(fields: "integrators") {
		integrators(filter: {type:{eq:$typefilter},status:{eq:"connected"}}) {
			type
			category
			integratorConfigs(filter: {name:{in:$integratorName}}) {
				name
				configs {
					key
					value
					encrypt
				}
			}
			featureConfigs {
				key
				value
			}
		}
	}
}
`

func QueryIntegratorsForOrgByTypeIfConnected(
	ctx_ context.Context,
	client_ graphql.Client,
	org string,
	typefilter string,
	integratorName []string,
) (*QueryIntegratorsForOrgByTypeIfConnectedResponse, error) {
	req_ := &graphql.Request{
		OpName: "QueryIntegratorsForOrgByTypeIfConnected",
		Query:  QueryIntegratorsForOrgByTypeIfConnected_Operation,
		Variables: &__QueryIntegratorsForOrgByTypeIfConnectedInput{
			Org:            org,
			Typefilter:     typefilter,
			IntegratorName: integratorName,
		},
	}
	var err_ error

	var data_ QueryIntegratorsForOrgByTypeIfConnectedResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}