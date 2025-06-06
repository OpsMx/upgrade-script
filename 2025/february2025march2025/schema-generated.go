// Code generated by github.com/Khan/genqlient, DO NOT EDIT.

package february2025march2025

import (
	"context"

	"github.com/Khan/genqlient/graphql"
)

// DeletePolicyDefinitionDeletePolicyDefinitionDeletePolicyDefinitionPayload includes the requested fields of the GraphQL type DeletePolicyDefinitionPayload.
type DeletePolicyDefinitionDeletePolicyDefinitionDeletePolicyDefinitionPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns DeletePolicyDefinitionDeletePolicyDefinitionDeletePolicyDefinitionPayload.NumUids, and is useful for accessing the field via an interface.
func (v *DeletePolicyDefinitionDeletePolicyDefinitionDeletePolicyDefinitionPayload) GetNumUids() *int {
	return v.NumUids
}

// DeletePolicyDefinitionResponse is returned by DeletePolicyDefinition on success.
type DeletePolicyDefinitionResponse struct {
	DeletePolicyDefinition *DeletePolicyDefinitionDeletePolicyDefinitionDeletePolicyDefinitionPayload `json:"deletePolicyDefinition"`
}

// GetDeletePolicyDefinition returns DeletePolicyDefinitionResponse.DeletePolicyDefinition, and is useful for accessing the field via an interface.
func (v *DeletePolicyDefinitionResponse) GetDeletePolicyDefinition() *DeletePolicyDefinitionDeletePolicyDefinitionDeletePolicyDefinitionPayload {
	return v.DeletePolicyDefinition
}

// DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload includes the requested fields of the GraphQL type DeletePolicyEnforcementPayload.
type DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload struct {
	Msg     string `json:"msg"`
	NumUids *int   `json:"numUids"`
}

// GetMsg returns DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload.Msg, and is useful for accessing the field via an interface.
func (v *DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload) GetMsg() string {
	return v.Msg
}

// GetNumUids returns DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload.NumUids, and is useful for accessing the field via an interface.
func (v *DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload) GetNumUids() *int {
	return v.NumUids
}

// DeletePolicyEnforcementResponse is returned by DeletePolicyEnforcement on success.
type DeletePolicyEnforcementResponse struct {
	DeletePolicyEnforcement *DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload `json:"deletePolicyEnforcement"`
}

// GetDeletePolicyEnforcement returns DeletePolicyEnforcementResponse.DeletePolicyEnforcement, and is useful for accessing the field via an interface.
func (v *DeletePolicyEnforcementResponse) GetDeletePolicyEnforcement() *DeletePolicyEnforcementDeletePolicyEnforcementDeletePolicyEnforcementPayload {
	return v.DeletePolicyEnforcement
}

// QueryPolicyEnforcementQueryPolicyEnforcement includes the requested fields of the GraphQL type PolicyEnforcement.
type QueryPolicyEnforcementQueryPolicyEnforcement struct {
	Id     *string                                                             `json:"id"`
	Policy *QueryPolicyEnforcementQueryPolicyEnforcementPolicyPolicyDefinition `json:"policy"`
}

// GetId returns QueryPolicyEnforcementQueryPolicyEnforcement.Id, and is useful for accessing the field via an interface.
func (v *QueryPolicyEnforcementQueryPolicyEnforcement) GetId() *string { return v.Id }

// GetPolicy returns QueryPolicyEnforcementQueryPolicyEnforcement.Policy, and is useful for accessing the field via an interface.
func (v *QueryPolicyEnforcementQueryPolicyEnforcement) GetPolicy() *QueryPolicyEnforcementQueryPolicyEnforcementPolicyPolicyDefinition {
	return v.Policy
}

// QueryPolicyEnforcementQueryPolicyEnforcementPolicyPolicyDefinition includes the requested fields of the GraphQL type PolicyDefinition.
type QueryPolicyEnforcementQueryPolicyEnforcementPolicyPolicyDefinition struct {
	Id string `json:"id"`
}

// GetId returns QueryPolicyEnforcementQueryPolicyEnforcementPolicyPolicyDefinition.Id, and is useful for accessing the field via an interface.
func (v *QueryPolicyEnforcementQueryPolicyEnforcementPolicyPolicyDefinition) GetId() string {
	return v.Id
}

// QueryPolicyEnforcementResponse is returned by QueryPolicyEnforcement on success.
type QueryPolicyEnforcementResponse struct {
	QueryPolicyEnforcement []*QueryPolicyEnforcementQueryPolicyEnforcement `json:"queryPolicyEnforcement"`
}

// GetQueryPolicyEnforcement returns QueryPolicyEnforcementResponse.QueryPolicyEnforcement, and is useful for accessing the field via an interface.
func (v *QueryPolicyEnforcementResponse) GetQueryPolicyEnforcement() []*QueryPolicyEnforcementQueryPolicyEnforcement {
	return v.QueryPolicyEnforcement
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistory includes the requested fields of the GraphQL type RunHistory.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistory struct {
	Id                    *string                                                                       `json:"id"`
	ApplicationDeployment *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment `json:"applicationDeployment"`
}

// GetId returns QueryRunHistoryWithApplicationDeploymentQueryRunHistory.Id, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistory) GetId() *string { return v.Id }

// GetApplicationDeployment returns QueryRunHistoryWithApplicationDeploymentQueryRunHistory.ApplicationDeployment, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistory) GetApplicationDeployment() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment {
	return v.ApplicationDeployment
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment includes the requested fields of the GraphQL type ApplicationDeployment.
// The GraphQL type's documentation follows.
//
// ApplicationDeployment tells us about the the artifact deployed along with its associated details.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment struct {
	ApplicationEnvironment *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment `json:"applicationEnvironment"`
	// toolsUsed contains tools of different stages of source, build, artifact and deploy along with some different tools
	ToolsUsed *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentToolsUsed `json:"toolsUsed"`
	// id is randomly assigned
	Id string `json:"id"`
}

// GetApplicationEnvironment returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment.ApplicationEnvironment, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment) GetApplicationEnvironment() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment {
	return v.ApplicationEnvironment
}

// GetToolsUsed returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment.ToolsUsed, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment) GetToolsUsed() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentToolsUsed {
	return v.ToolsUsed
}

// GetId returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment.Id, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeployment) GetId() string {
	return v.Id
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment includes the requested fields of the GraphQL type ApplicationEnvironment.
// The GraphQL type's documentation follows.
//
// ApplicationEnvironment is a running instance of an application down to the level of a namespace or its non k8s equivalent.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment struct {
	Namespace        string                                                                                                              `json:"namespace"`
	Application      *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication      `json:"application"`
	DeploymentTarget *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentDeploymentTarget `json:"deploymentTarget"`
	// environment denotes whether it is dev, prod, staging, non-prod etc
	Environment *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentEnvironment `json:"environment"`
}

// GetNamespace returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment.Namespace, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment) GetNamespace() string {
	return v.Namespace
}

// GetApplication returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment.Application, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment) GetApplication() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication {
	return v.Application
}

// GetDeploymentTarget returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment.DeploymentTarget, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment) GetDeploymentTarget() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentDeploymentTarget {
	return v.DeploymentTarget
}

// GetEnvironment returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment.Environment, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironment) GetEnvironment() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentEnvironment {
	return v.Environment
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication includes the requested fields of the GraphQL type Application.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication struct {
	Team *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplicationTeam `json:"team"`
	Name string                                                                                                             `json:"name"`
}

// GetTeam returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication.Team, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication) GetTeam() *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplicationTeam {
	return v.Team
}

// GetName returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication.Name, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplication) GetName() string {
	return v.Name
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplicationTeam includes the requested fields of the GraphQL type Team.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplicationTeam struct {
	// id is randomly assigned
	Id string `json:"id"`
}

// GetId returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplicationTeam.Id, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentApplicationTeam) GetId() string {
	return v.Id
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentDeploymentTarget includes the requested fields of the GraphQL type DeploymentTarget.
// The GraphQL type's documentation follows.
//
// DeploymentTarget describes a single place that things can be deployed into,
// such as an AWS account or a Kubernetes cluster.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentDeploymentTarget struct {
	Name string `json:"name"`
}

// GetName returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentDeploymentTarget.Name, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentDeploymentTarget) GetName() string {
	return v.Name
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentEnvironment includes the requested fields of the GraphQL type Environment.
// The GraphQL type's documentation follows.
//
// Environment can be things like dev, prod, staging etc.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentEnvironment struct {
	Purpose string `json:"purpose"`
}

// GetPurpose returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentEnvironment.Purpose, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentApplicationEnvironmentEnvironment) GetPurpose() string {
	return v.Purpose
}

// QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentToolsUsed includes the requested fields of the GraphQL type ToolsUsed.
type QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentToolsUsed struct {
	Sbom string `json:"sbom"`
}

// GetSbom returns QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentToolsUsed.Sbom, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentQueryRunHistoryApplicationDeploymentToolsUsed) GetSbom() string {
	return v.Sbom
}

// QueryRunHistoryWithApplicationDeploymentResponse is returned by QueryRunHistoryWithApplicationDeployment on success.
type QueryRunHistoryWithApplicationDeploymentResponse struct {
	QueryRunHistory []*QueryRunHistoryWithApplicationDeploymentQueryRunHistory `json:"queryRunHistory"`
}

// GetQueryRunHistory returns QueryRunHistoryWithApplicationDeploymentResponse.QueryRunHistory, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithApplicationDeploymentResponse) GetQueryRunHistory() []*QueryRunHistoryWithApplicationDeploymentQueryRunHistory {
	return v.QueryRunHistory
}

// QueryRunHistoryWithArtifactScanDataQueryRunHistory includes the requested fields of the GraphQL type RunHistory.
type QueryRunHistoryWithArtifactScanDataQueryRunHistory struct {
	Id           *string                                                                         `json:"id"`
	ArtifactScan *QueryRunHistoryWithArtifactScanDataQueryRunHistoryArtifactScanArtifactScanData `json:"artifactScan"`
}

// GetId returns QueryRunHistoryWithArtifactScanDataQueryRunHistory.Id, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithArtifactScanDataQueryRunHistory) GetId() *string { return v.Id }

// GetArtifactScan returns QueryRunHistoryWithArtifactScanDataQueryRunHistory.ArtifactScan, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithArtifactScanDataQueryRunHistory) GetArtifactScan() *QueryRunHistoryWithArtifactScanDataQueryRunHistoryArtifactScanArtifactScanData {
	return v.ArtifactScan
}

// QueryRunHistoryWithArtifactScanDataQueryRunHistoryArtifactScanArtifactScanData includes the requested fields of the GraphQL type ArtifactScanData.
type QueryRunHistoryWithArtifactScanDataQueryRunHistoryArtifactScanArtifactScanData struct {
	Tool string `json:"tool"`
}

// GetTool returns QueryRunHistoryWithArtifactScanDataQueryRunHistoryArtifactScanArtifactScanData.Tool, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithArtifactScanDataQueryRunHistoryArtifactScanArtifactScanData) GetTool() string {
	return v.Tool
}

// QueryRunHistoryWithArtifactScanDataResponse is returned by QueryRunHistoryWithArtifactScanData on success.
type QueryRunHistoryWithArtifactScanDataResponse struct {
	QueryRunHistory []*QueryRunHistoryWithArtifactScanDataQueryRunHistory `json:"queryRunHistory"`
}

// GetQueryRunHistory returns QueryRunHistoryWithArtifactScanDataResponse.QueryRunHistory, and is useful for accessing the field via an interface.
func (v *QueryRunHistoryWithArtifactScanDataResponse) GetQueryRunHistory() []*QueryRunHistoryWithArtifactScanDataQueryRunHistory {
	return v.QueryRunHistory
}

// SetKubescapeLatestFileTSNodeToDefaultResponse is returned by SetKubescapeLatestFileTSNodeToDefault on success.
type SetKubescapeLatestFileTSNodeToDefaultResponse struct {
	UpdateDeploymentTarget *SetKubescapeLatestFileTSNodeToDefaultUpdateDeploymentTargetUpdateDeploymentTargetPayload `json:"updateDeploymentTarget"`
}

// GetUpdateDeploymentTarget returns SetKubescapeLatestFileTSNodeToDefaultResponse.UpdateDeploymentTarget, and is useful for accessing the field via an interface.
func (v *SetKubescapeLatestFileTSNodeToDefaultResponse) GetUpdateDeploymentTarget() *SetKubescapeLatestFileTSNodeToDefaultUpdateDeploymentTargetUpdateDeploymentTargetPayload {
	return v.UpdateDeploymentTarget
}

// SetKubescapeLatestFileTSNodeToDefaultUpdateDeploymentTargetUpdateDeploymentTargetPayload includes the requested fields of the GraphQL type UpdateDeploymentTargetPayload.
type SetKubescapeLatestFileTSNodeToDefaultUpdateDeploymentTargetUpdateDeploymentTargetPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns SetKubescapeLatestFileTSNodeToDefaultUpdateDeploymentTargetUpdateDeploymentTargetPayload.NumUids, and is useful for accessing the field via an interface.
func (v *SetKubescapeLatestFileTSNodeToDefaultUpdateDeploymentTargetUpdateDeploymentTargetPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateArtifactRunHistoryResponse is returned by UpdateArtifactRunHistory on success.
type UpdateArtifactRunHistoryResponse struct {
	UpdateRunHistory *UpdateArtifactRunHistoryUpdateRunHistoryUpdateRunHistoryPayload `json:"updateRunHistory"`
}

// GetUpdateRunHistory returns UpdateArtifactRunHistoryResponse.UpdateRunHistory, and is useful for accessing the field via an interface.
func (v *UpdateArtifactRunHistoryResponse) GetUpdateRunHistory() *UpdateArtifactRunHistoryUpdateRunHistoryUpdateRunHistoryPayload {
	return v.UpdateRunHistory
}

// UpdateArtifactRunHistoryUpdateRunHistoryUpdateRunHistoryPayload includes the requested fields of the GraphQL type UpdateRunHistoryPayload.
type UpdateArtifactRunHistoryUpdateRunHistoryUpdateRunHistoryPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateArtifactRunHistoryUpdateRunHistoryUpdateRunHistoryPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateArtifactRunHistoryUpdateRunHistoryUpdateRunHistoryPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateBlockedApplicationDeploymentResponse is returned by UpdateBlockedApplicationDeployment on success.
type UpdateBlockedApplicationDeploymentResponse struct {
	UpdateApplicationDeployment *UpdateBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload `json:"updateApplicationDeployment"`
}

// GetUpdateApplicationDeployment returns UpdateBlockedApplicationDeploymentResponse.UpdateApplicationDeployment, and is useful for accessing the field via an interface.
func (v *UpdateBlockedApplicationDeploymentResponse) GetUpdateApplicationDeployment() *UpdateBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload {
	return v.UpdateApplicationDeployment
}

// UpdateBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload includes the requested fields of the GraphQL type UpdateApplicationDeploymentPayload.
type UpdateBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateNonBlockedApplicationDeploymentResponse is returned by UpdateNonBlockedApplicationDeployment on success.
type UpdateNonBlockedApplicationDeploymentResponse struct {
	UpdateApplicationDeployment *UpdateNonBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload `json:"updateApplicationDeployment"`
}

// GetUpdateApplicationDeployment returns UpdateNonBlockedApplicationDeploymentResponse.UpdateApplicationDeployment, and is useful for accessing the field via an interface.
func (v *UpdateNonBlockedApplicationDeploymentResponse) GetUpdateApplicationDeployment() *UpdateNonBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload {
	return v.UpdateApplicationDeployment
}

// UpdateNonBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload includes the requested fields of the GraphQL type UpdateApplicationDeploymentPayload.
type UpdateNonBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateNonBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateNonBlockedApplicationDeploymentUpdateApplicationDeploymentUpdateApplicationDeploymentPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateRunHistoryDeploymentFieldsResponse is returned by UpdateRunHistoryDeploymentFields on success.
type UpdateRunHistoryDeploymentFieldsResponse struct {
	UpdateRunHistory *UpdateRunHistoryDeploymentFieldsUpdateRunHistoryUpdateRunHistoryPayload `json:"updateRunHistory"`
}

// GetUpdateRunHistory returns UpdateRunHistoryDeploymentFieldsResponse.UpdateRunHistory, and is useful for accessing the field via an interface.
func (v *UpdateRunHistoryDeploymentFieldsResponse) GetUpdateRunHistory() *UpdateRunHistoryDeploymentFieldsUpdateRunHistoryUpdateRunHistoryPayload {
	return v.UpdateRunHistory
}

// UpdateRunHistoryDeploymentFieldsUpdateRunHistoryUpdateRunHistoryPayload includes the requested fields of the GraphQL type UpdateRunHistoryPayload.
type UpdateRunHistoryDeploymentFieldsUpdateRunHistoryUpdateRunHistoryPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateRunHistoryDeploymentFieldsUpdateRunHistoryUpdateRunHistoryPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateRunHistoryDeploymentFieldsUpdateRunHistoryUpdateRunHistoryPayload) GetNumUids() *int {
	return v.NumUids
}

// __DeletePolicyEnforcementInput is used internally by genqlient
type __DeletePolicyEnforcementInput struct {
	Id *string `json:"id"`
}

// GetId returns __DeletePolicyEnforcementInput.Id, and is useful for accessing the field via an interface.
func (v *__DeletePolicyEnforcementInput) GetId() *string { return v.Id }

// __UpdateArtifactRunHistoryInput is used internally by genqlient
type __UpdateArtifactRunHistoryInput struct {
	RunHistoryID *string `json:"runHistoryID"`
	SbomTool     string  `json:"sbomTool"`
}

// GetRunHistoryID returns __UpdateArtifactRunHistoryInput.RunHistoryID, and is useful for accessing the field via an interface.
func (v *__UpdateArtifactRunHistoryInput) GetRunHistoryID() *string { return v.RunHistoryID }

// GetSbomTool returns __UpdateArtifactRunHistoryInput.SbomTool, and is useful for accessing the field via an interface.
func (v *__UpdateArtifactRunHistoryInput) GetSbomTool() string { return v.SbomTool }

// __UpdateRunHistoryDeploymentFieldsInput is used internally by genqlient
type __UpdateRunHistoryDeploymentFieldsInput struct {
	RunHistoryID *string `json:"runHistoryID"`
	DeploymentID string  `json:"deploymentID"`
	SbomTool     string  `json:"sbomTool"`
	Namespace    string  `json:"namespace"`
	Account      string  `json:"account"`
	Cluster      string  `json:"cluster"`
	Application  string  `json:"application"`
	TeamID       string  `json:"teamID"`
}

// GetRunHistoryID returns __UpdateRunHistoryDeploymentFieldsInput.RunHistoryID, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetRunHistoryID() *string { return v.RunHistoryID }

// GetDeploymentID returns __UpdateRunHistoryDeploymentFieldsInput.DeploymentID, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetDeploymentID() string { return v.DeploymentID }

// GetSbomTool returns __UpdateRunHistoryDeploymentFieldsInput.SbomTool, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetSbomTool() string { return v.SbomTool }

// GetNamespace returns __UpdateRunHistoryDeploymentFieldsInput.Namespace, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetNamespace() string { return v.Namespace }

// GetAccount returns __UpdateRunHistoryDeploymentFieldsInput.Account, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetAccount() string { return v.Account }

// GetCluster returns __UpdateRunHistoryDeploymentFieldsInput.Cluster, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetCluster() string { return v.Cluster }

// GetApplication returns __UpdateRunHistoryDeploymentFieldsInput.Application, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetApplication() string { return v.Application }

// GetTeamID returns __UpdateRunHistoryDeploymentFieldsInput.TeamID, and is useful for accessing the field via an interface.
func (v *__UpdateRunHistoryDeploymentFieldsInput) GetTeamID() string { return v.TeamID }

// The mutation executed by DeletePolicyDefinition.
const DeletePolicyDefinition_Operation = `
mutation DeletePolicyDefinition {
	deletePolicyDefinition(filter: {id:{in:["422","423","436","437","438","441","442","443","444","445","446","448","450","452"]}}) {
		numUids
	}
}
`

func DeletePolicyDefinition(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *DeletePolicyDefinitionResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "DeletePolicyDefinition",
		Query:  DeletePolicyDefinition_Operation,
	}

	data_ = &DeletePolicyDefinitionResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The mutation executed by DeletePolicyEnforcement.
const DeletePolicyEnforcement_Operation = `
mutation DeletePolicyEnforcement ($id: ID!) {
	deletePolicyEnforcement(filter: {id:[$id]}) {
		msg
		numUids
	}
}
`

func DeletePolicyEnforcement(
	ctx_ context.Context,
	client_ graphql.Client,
	id *string,
) (data_ *DeletePolicyEnforcementResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "DeletePolicyEnforcement",
		Query:  DeletePolicyEnforcement_Operation,
		Variables: &__DeletePolicyEnforcementInput{
			Id: id,
		},
	}

	data_ = &DeletePolicyEnforcementResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The query executed by QueryPolicyEnforcement.
const QueryPolicyEnforcement_Operation = `
query QueryPolicyEnforcement {
	queryPolicyEnforcement @cascade {
		id
		policy(filter: {id:{in:["422","423","436","437","438","441","442","443","444","445","446","448","450","452"]}}) {
			id
		}
	}
}
`

func QueryPolicyEnforcement(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *QueryPolicyEnforcementResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "QueryPolicyEnforcement",
		Query:  QueryPolicyEnforcement_Operation,
	}

	data_ = &QueryPolicyEnforcementResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The query executed by QueryRunHistoryWithApplicationDeployment.
const QueryRunHistoryWithApplicationDeployment_Operation = `
query QueryRunHistoryWithApplicationDeployment {
	queryRunHistory @cascade {
		id
		applicationDeployment {
			applicationEnvironment {
				namespace
				application {
					team {
						id
					}
					name
				}
				deploymentTarget {
					name
				}
				environment {
					purpose
				}
			}
			toolsUsed {
				sbom
			}
			id
		}
	}
}
`

func QueryRunHistoryWithApplicationDeployment(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *QueryRunHistoryWithApplicationDeploymentResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "QueryRunHistoryWithApplicationDeployment",
		Query:  QueryRunHistoryWithApplicationDeployment_Operation,
	}

	data_ = &QueryRunHistoryWithApplicationDeploymentResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The query executed by QueryRunHistoryWithArtifactScanData.
const QueryRunHistoryWithArtifactScanData_Operation = `
query QueryRunHistoryWithArtifactScanData {
	queryRunHistory @cascade {
		id
		artifactScan {
			tool
		}
	}
}
`

func QueryRunHistoryWithArtifactScanData(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *QueryRunHistoryWithArtifactScanDataResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "QueryRunHistoryWithArtifactScanData",
		Query:  QueryRunHistoryWithArtifactScanData_Operation,
	}

	data_ = &QueryRunHistoryWithArtifactScanDataResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The mutation executed by SetKubescapeLatestFileTSNodeToDefault.
const SetKubescapeLatestFileTSNodeToDefault_Operation = `
mutation SetKubescapeLatestFileTSNodeToDefault {
	updateDeploymentTarget(input: {set:{kubescapeLatestFileTS:""},filter:{has:name}}) {
		numUids
	}
}
`

func SetKubescapeLatestFileTSNodeToDefault(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *SetKubescapeLatestFileTSNodeToDefaultResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "SetKubescapeLatestFileTSNodeToDefault",
		Query:  SetKubescapeLatestFileTSNodeToDefault_Operation,
	}

	data_ = &SetKubescapeLatestFileTSNodeToDefaultResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The mutation executed by UpdateArtifactRunHistory.
const UpdateArtifactRunHistory_Operation = `
mutation UpdateArtifactRunHistory ($runHistoryID: ID!, $sbomTool: String!) {
	updateRunHistory(input: {filter:{id:[$runHistoryID]},set:{SbomTool:$sbomTool}}) {
		numUids
	}
}
`

func UpdateArtifactRunHistory(
	ctx_ context.Context,
	client_ graphql.Client,
	runHistoryID *string,
	sbomTool string,
) (data_ *UpdateArtifactRunHistoryResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "UpdateArtifactRunHistory",
		Query:  UpdateArtifactRunHistory_Operation,
		Variables: &__UpdateArtifactRunHistoryInput{
			RunHistoryID: runHistoryID,
			SbomTool:     sbomTool,
		},
	}

	data_ = &UpdateArtifactRunHistoryResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The mutation executed by UpdateBlockedApplicationDeployment.
const UpdateBlockedApplicationDeployment_Operation = `
mutation UpdateBlockedApplicationDeployment {
	updateApplicationDeployment(input: {set:{firewall:true,deploymentResult:"blocked"},filter:{deploymentStage:{eq:blocked}}}) {
		numUids
	}
}
`

func UpdateBlockedApplicationDeployment(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *UpdateBlockedApplicationDeploymentResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "UpdateBlockedApplicationDeployment",
		Query:  UpdateBlockedApplicationDeployment_Operation,
	}

	data_ = &UpdateBlockedApplicationDeploymentResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The mutation executed by UpdateNonBlockedApplicationDeployment.
const UpdateNonBlockedApplicationDeployment_Operation = `
mutation UpdateNonBlockedApplicationDeployment {
	updateApplicationDeployment(input: {set:{firewall:false,deploymentResult:"passed"},filter:{not:{deploymentStage:{eq:blocked}}}}) {
		numUids
	}
}
`

func UpdateNonBlockedApplicationDeployment(
	ctx_ context.Context,
	client_ graphql.Client,
) (data_ *UpdateNonBlockedApplicationDeploymentResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "UpdateNonBlockedApplicationDeployment",
		Query:  UpdateNonBlockedApplicationDeployment_Operation,
	}

	data_ = &UpdateNonBlockedApplicationDeploymentResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}

// The mutation executed by UpdateRunHistoryDeploymentFields.
const UpdateRunHistoryDeploymentFields_Operation = `
mutation UpdateRunHistoryDeploymentFields ($runHistoryID: ID!, $deploymentID: String!, $sbomTool: String!, $namespace: String!, $account: String!, $cluster: String!, $application: String!, $teamID: String!) {
	updateRunHistory(input: {filter:{id:[$runHistoryID]},set:{DeploymentID:$deploymentID,SbomTool:$sbomTool,Namespace:$namespace,Account:$account,Cluster:$cluster,Application:$application,TeamID:$teamID}}) {
		numUids
	}
}
`

func UpdateRunHistoryDeploymentFields(
	ctx_ context.Context,
	client_ graphql.Client,
	runHistoryID *string,
	deploymentID string,
	sbomTool string,
	namespace string,
	account string,
	cluster string,
	application string,
	teamID string,
) (data_ *UpdateRunHistoryDeploymentFieldsResponse, err_ error) {
	req_ := &graphql.Request{
		OpName: "UpdateRunHistoryDeploymentFields",
		Query:  UpdateRunHistoryDeploymentFields_Operation,
		Variables: &__UpdateRunHistoryDeploymentFieldsInput{
			RunHistoryID: runHistoryID,
			DeploymentID: deploymentID,
			SbomTool:     sbomTool,
			Namespace:    namespace,
			Account:      account,
			Cluster:      cluster,
			Application:  application,
			TeamID:       teamID,
		},
	}

	data_ = &UpdateRunHistoryDeploymentFieldsResponse{}
	resp_ := &graphql.Response{Data: data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return data_, err_
}
