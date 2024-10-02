// Code generated by github.com/Khan/genqlient, DO NOT EDIT.

package august2024v2september2024

import (
	"context"

	"github.com/Khan/genqlient/graphql"
)

// QueryArtifactNameAndTagQueryArtifactScanData includes the requested fields of the GraphQL type ArtifactScanData.
type QueryArtifactNameAndTagQueryArtifactScanData struct {
	Id              string                                                               `json:"id"`
	ArtifactDetails *QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact `json:"artifactDetails"`
}

// GetId returns QueryArtifactNameAndTagQueryArtifactScanData.Id, and is useful for accessing the field via an interface.
func (v *QueryArtifactNameAndTagQueryArtifactScanData) GetId() string { return v.Id }

// GetArtifactDetails returns QueryArtifactNameAndTagQueryArtifactScanData.ArtifactDetails, and is useful for accessing the field via an interface.
func (v *QueryArtifactNameAndTagQueryArtifactScanData) GetArtifactDetails() *QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact {
	return v.ArtifactDetails
}

// QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact includes the requested fields of the GraphQL type Artifact.
type QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact struct {
	ArtifactName string `json:"artifactName"`
	ArtifactTag  string `json:"artifactTag"`
}

// GetArtifactName returns QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact.ArtifactName, and is useful for accessing the field via an interface.
func (v *QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact) GetArtifactName() string {
	return v.ArtifactName
}

// GetArtifactTag returns QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact.ArtifactTag, and is useful for accessing the field via an interface.
func (v *QueryArtifactNameAndTagQueryArtifactScanDataArtifactDetailsArtifact) GetArtifactTag() string {
	return v.ArtifactTag
}

// QueryArtifactNameAndTagResponse is returned by QueryArtifactNameAndTag on success.
type QueryArtifactNameAndTagResponse struct {
	QueryArtifactScanData []*QueryArtifactNameAndTagQueryArtifactScanData `json:"queryArtifactScanData"`
}

// GetQueryArtifactScanData returns QueryArtifactNameAndTagResponse.QueryArtifactScanData, and is useful for accessing the field via an interface.
func (v *QueryArtifactNameAndTagResponse) GetQueryArtifactScanData() []*QueryArtifactNameAndTagQueryArtifactScanData {
	return v.QueryArtifactScanData
}

// UpdateArtifactNameTagResponse is returned by UpdateArtifactNameTag on success.
type UpdateArtifactNameTagResponse struct {
	UpdateArtifactScanData *UpdateArtifactNameTagUpdateArtifactScanDataUpdateArtifactScanDataPayload `json:"updateArtifactScanData"`
}

// GetUpdateArtifactScanData returns UpdateArtifactNameTagResponse.UpdateArtifactScanData, and is useful for accessing the field via an interface.
func (v *UpdateArtifactNameTagResponse) GetUpdateArtifactScanData() *UpdateArtifactNameTagUpdateArtifactScanDataUpdateArtifactScanDataPayload {
	return v.UpdateArtifactScanData
}

// UpdateArtifactNameTagUpdateArtifactScanDataUpdateArtifactScanDataPayload includes the requested fields of the GraphQL type UpdateArtifactScanDataPayload.
type UpdateArtifactNameTagUpdateArtifactScanDataUpdateArtifactScanDataPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateArtifactNameTagUpdateArtifactScanDataUpdateArtifactScanDataPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateArtifactNameTagUpdateArtifactScanDataUpdateArtifactScanDataPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateForcePolicyForGraphqlToolResponse is returned by UpdateForcePolicyForGraphqlTool on success.
type UpdateForcePolicyForGraphqlToolResponse struct {
	UpdatePolicyEnforcement *UpdateForcePolicyForGraphqlToolUpdatePolicyEnforcementUpdatePolicyEnforcementPayload `json:"updatePolicyEnforcement"`
}

// GetUpdatePolicyEnforcement returns UpdateForcePolicyForGraphqlToolResponse.UpdatePolicyEnforcement, and is useful for accessing the field via an interface.
func (v *UpdateForcePolicyForGraphqlToolResponse) GetUpdatePolicyEnforcement() *UpdateForcePolicyForGraphqlToolUpdatePolicyEnforcementUpdatePolicyEnforcementPayload {
	return v.UpdatePolicyEnforcement
}

// UpdateForcePolicyForGraphqlToolUpdatePolicyEnforcementUpdatePolicyEnforcementPayload includes the requested fields of the GraphQL type UpdatePolicyEnforcementPayload.
type UpdateForcePolicyForGraphqlToolUpdatePolicyEnforcementUpdatePolicyEnforcementPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateForcePolicyForGraphqlToolUpdatePolicyEnforcementUpdatePolicyEnforcementPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateForcePolicyForGraphqlToolUpdatePolicyEnforcementUpdatePolicyEnforcementPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityForCriticalResponse is returned by UpdateVulnerabilityForCritical on success.
type UpdateVulnerabilityForCriticalResponse struct {
	UpdateVulnerability *UpdateVulnerabilityForCriticalUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityForCriticalResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForCriticalResponse) GetUpdateVulnerability() *UpdateVulnerabilityForCriticalUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityForCriticalUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityForCriticalUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityForCriticalUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForCriticalUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityForHighResponse is returned by UpdateVulnerabilityForHigh on success.
type UpdateVulnerabilityForHighResponse struct {
	UpdateVulnerability *UpdateVulnerabilityForHighUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityForHighResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForHighResponse) GetUpdateVulnerability() *UpdateVulnerabilityForHighUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityForHighUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityForHighUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityForHighUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForHighUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityForLowResponse is returned by UpdateVulnerabilityForLow on success.
type UpdateVulnerabilityForLowResponse struct {
	UpdateVulnerability *UpdateVulnerabilityForLowUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityForLowResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForLowResponse) GetUpdateVulnerability() *UpdateVulnerabilityForLowUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityForLowUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityForLowUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityForLowUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForLowUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityForMediumResponse is returned by UpdateVulnerabilityForMedium on success.
type UpdateVulnerabilityForMediumResponse struct {
	UpdateVulnerability *UpdateVulnerabilityForMediumUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityForMediumResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForMediumResponse) GetUpdateVulnerability() *UpdateVulnerabilityForMediumUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityForMediumUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityForMediumUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityForMediumUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForMediumUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityForOthersResponse is returned by UpdateVulnerabilityForOthers on success.
type UpdateVulnerabilityForOthersResponse struct {
	UpdateVulnerability *UpdateVulnerabilityForOthersUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityForOthersResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForOthersResponse) GetUpdateVulnerability() *UpdateVulnerabilityForOthersUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityForOthersUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityForOthersUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityForOthersUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForOthersUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityForUnknownResponse is returned by UpdateVulnerabilityForUnknown on success.
type UpdateVulnerabilityForUnknownResponse struct {
	UpdateVulnerability *UpdateVulnerabilityForUnknownUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityForUnknownResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForUnknownResponse) GetUpdateVulnerability() *UpdateVulnerabilityForUnknownUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityForUnknownUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityForUnknownUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityForUnknownUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityForUnknownUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityPriority1Response is returned by UpdateVulnerabilityPriority1 on success.
type UpdateVulnerabilityPriority1Response struct {
	UpdateVulnerability *UpdateVulnerabilityPriority1UpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityPriority1Response.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority1Response) GetUpdateVulnerability() *UpdateVulnerabilityPriority1UpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityPriority1UpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityPriority1UpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityPriority1UpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority1UpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityPriority1plusResponse is returned by UpdateVulnerabilityPriority1plus on success.
type UpdateVulnerabilityPriority1plusResponse struct {
	UpdateVulnerability *UpdateVulnerabilityPriority1plusUpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityPriority1plusResponse.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority1plusResponse) GetUpdateVulnerability() *UpdateVulnerabilityPriority1plusUpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityPriority1plusUpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityPriority1plusUpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityPriority1plusUpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority1plusUpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityPriority2Response is returned by UpdateVulnerabilityPriority2 on success.
type UpdateVulnerabilityPriority2Response struct {
	UpdateVulnerability *UpdateVulnerabilityPriority2UpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityPriority2Response.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority2Response) GetUpdateVulnerability() *UpdateVulnerabilityPriority2UpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityPriority2UpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityPriority2UpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityPriority2UpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority2UpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityPriority3Response is returned by UpdateVulnerabilityPriority3 on success.
type UpdateVulnerabilityPriority3Response struct {
	UpdateVulnerability *UpdateVulnerabilityPriority3UpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityPriority3Response.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority3Response) GetUpdateVulnerability() *UpdateVulnerabilityPriority3UpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityPriority3UpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityPriority3UpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityPriority3UpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority3UpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// UpdateVulnerabilityPriority4Response is returned by UpdateVulnerabilityPriority4 on success.
type UpdateVulnerabilityPriority4Response struct {
	UpdateVulnerability *UpdateVulnerabilityPriority4UpdateVulnerabilityUpdateVulnerabilityPayload `json:"updateVulnerability"`
}

// GetUpdateVulnerability returns UpdateVulnerabilityPriority4Response.UpdateVulnerability, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority4Response) GetUpdateVulnerability() *UpdateVulnerabilityPriority4UpdateVulnerabilityUpdateVulnerabilityPayload {
	return v.UpdateVulnerability
}

// UpdateVulnerabilityPriority4UpdateVulnerabilityUpdateVulnerabilityPayload includes the requested fields of the GraphQL type UpdateVulnerabilityPayload.
type UpdateVulnerabilityPriority4UpdateVulnerabilityUpdateVulnerabilityPayload struct {
	NumUids *int `json:"numUids"`
}

// GetNumUids returns UpdateVulnerabilityPriority4UpdateVulnerabilityUpdateVulnerabilityPayload.NumUids, and is useful for accessing the field via an interface.
func (v *UpdateVulnerabilityPriority4UpdateVulnerabilityUpdateVulnerabilityPayload) GetNumUids() *int {
	return v.NumUids
}

// __UpdateArtifactNameTagInput is used internally by genqlient
type __UpdateArtifactNameTagInput struct {
	Id              string `json:"id"`
	ArtifactNameTag string `json:"artifactNameTag"`
}

// GetId returns __UpdateArtifactNameTagInput.Id, and is useful for accessing the field via an interface.
func (v *__UpdateArtifactNameTagInput) GetId() string { return v.Id }

// GetArtifactNameTag returns __UpdateArtifactNameTagInput.ArtifactNameTag, and is useful for accessing the field via an interface.
func (v *__UpdateArtifactNameTagInput) GetArtifactNameTag() string { return v.ArtifactNameTag }

// The query or mutation executed by QueryArtifactNameAndTag.
const QueryArtifactNameAndTag_Operation = `
query QueryArtifactNameAndTag {
	queryArtifactScanData {
		id
		artifactDetails {
			artifactName
			artifactTag
		}
	}
}
`

func QueryArtifactNameAndTag(
	ctx_ context.Context,
	client_ graphql.Client,
) (*QueryArtifactNameAndTagResponse, error) {
	req_ := &graphql.Request{
		OpName: "QueryArtifactNameAndTag",
		Query:  QueryArtifactNameAndTag_Operation,
	}
	var err_ error

	var data_ QueryArtifactNameAndTagResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateArtifactNameTag.
const UpdateArtifactNameTag_Operation = `
mutation UpdateArtifactNameTag ($id: String!, $artifactNameTag: String!) {
	updateArtifactScanData(input: {set:{artifactNameTag:$artifactNameTag},filter:{id:{eq:$id}}}) {
		numUids
	}
}
`

func UpdateArtifactNameTag(
	ctx_ context.Context,
	client_ graphql.Client,
	id string,
	artifactNameTag string,
) (*UpdateArtifactNameTagResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateArtifactNameTag",
		Query:  UpdateArtifactNameTag_Operation,
		Variables: &__UpdateArtifactNameTagInput{
			Id:              id,
			ArtifactNameTag: artifactNameTag,
		},
	}
	var err_ error

	var data_ UpdateArtifactNameTagResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateForcePolicyForGraphqlTool.
const UpdateForcePolicyForGraphqlTool_Operation = `
mutation UpdateForcePolicyForGraphqlTool {
	updatePolicyEnforcement(input: {set:{forceApply:true},filter:{datasourceTool:{eq:"graphql"}}}) {
		numUids
	}
}
`

func UpdateForcePolicyForGraphqlTool(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateForcePolicyForGraphqlToolResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateForcePolicyForGraphqlTool",
		Query:  UpdateForcePolicyForGraphqlTool_Operation,
	}
	var err_ error

	var data_ UpdateForcePolicyForGraphqlToolResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityForCritical.
const UpdateVulnerabilityForCritical_Operation = `
mutation UpdateVulnerabilityForCritical {
	updateVulnerability(input: {set:{ratingsInt:0},filter:{ratings:{eq:critical}}}) {
		numUids
	}
}
`

func UpdateVulnerabilityForCritical(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityForCriticalResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityForCritical",
		Query:  UpdateVulnerabilityForCritical_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityForCriticalResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityForHigh.
const UpdateVulnerabilityForHigh_Operation = `
mutation UpdateVulnerabilityForHigh {
	updateVulnerability(input: {set:{ratingsInt:1},filter:{ratings:{eq:high}}}) {
		numUids
	}
}
`

func UpdateVulnerabilityForHigh(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityForHighResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityForHigh",
		Query:  UpdateVulnerabilityForHigh_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityForHighResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityForLow.
const UpdateVulnerabilityForLow_Operation = `
mutation UpdateVulnerabilityForLow {
	updateVulnerability(input: {set:{ratingsInt:3},filter:{ratings:{eq:low}}}) {
		numUids
	}
}
`

func UpdateVulnerabilityForLow(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityForLowResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityForLow",
		Query:  UpdateVulnerabilityForLow_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityForLowResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityForMedium.
const UpdateVulnerabilityForMedium_Operation = `
mutation UpdateVulnerabilityForMedium {
	updateVulnerability(input: {set:{ratingsInt:2},filter:{ratings:{eq:medium}}}) {
		numUids
	}
}
`

func UpdateVulnerabilityForMedium(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityForMediumResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityForMedium",
		Query:  UpdateVulnerabilityForMedium_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityForMediumResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityForOthers.
const UpdateVulnerabilityForOthers_Operation = `
mutation UpdateVulnerabilityForOthers {
	updateVulnerability(input: {set:{ratingsInt:5},filter:{not:{ratings:{in:[critical,high,medium,low,unknown]}}}}) {
		numUids
	}
}
`

func UpdateVulnerabilityForOthers(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityForOthersResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityForOthers",
		Query:  UpdateVulnerabilityForOthers_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityForOthersResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityForUnknown.
const UpdateVulnerabilityForUnknown_Operation = `
mutation UpdateVulnerabilityForUnknown {
	updateVulnerability(input: {set:{ratingsInt:4},filter:{ratings:{eq:unknown}}}) {
		numUids
	}
}
`

func UpdateVulnerabilityForUnknown(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityForUnknownResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityForUnknown",
		Query:  UpdateVulnerabilityForUnknown_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityForUnknownResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityPriority1.
const UpdateVulnerabilityPriority1_Operation = `
mutation UpdateVulnerabilityPriority1 {
	updateVulnerability(input: {filter:{priority:{eq:"Priority 1"}},set:{priorityInt:1}}) {
		numUids
	}
}
`

func UpdateVulnerabilityPriority1(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityPriority1Response, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityPriority1",
		Query:  UpdateVulnerabilityPriority1_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityPriority1Response
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityPriority1plus.
const UpdateVulnerabilityPriority1plus_Operation = `
mutation UpdateVulnerabilityPriority1plus {
	updateVulnerability(input: {filter:{priority:{eq:"Priority 1+"}},set:{priorityInt:0}}) {
		numUids
	}
}
`

func UpdateVulnerabilityPriority1plus(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityPriority1plusResponse, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityPriority1plus",
		Query:  UpdateVulnerabilityPriority1plus_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityPriority1plusResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityPriority2.
const UpdateVulnerabilityPriority2_Operation = `
mutation UpdateVulnerabilityPriority2 {
	updateVulnerability(input: {filter:{priority:{eq:"Priority 2"}},set:{priorityInt:2}}) {
		numUids
	}
}
`

func UpdateVulnerabilityPriority2(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityPriority2Response, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityPriority2",
		Query:  UpdateVulnerabilityPriority2_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityPriority2Response
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityPriority3.
const UpdateVulnerabilityPriority3_Operation = `
mutation UpdateVulnerabilityPriority3 {
	updateVulnerability(input: {filter:{priority:{eq:"Priority 3"}},set:{priorityInt:3}}) {
		numUids
	}
}
`

func UpdateVulnerabilityPriority3(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityPriority3Response, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityPriority3",
		Query:  UpdateVulnerabilityPriority3_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityPriority3Response
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}

// The query or mutation executed by UpdateVulnerabilityPriority4.
const UpdateVulnerabilityPriority4_Operation = `
mutation UpdateVulnerabilityPriority4 {
	updateVulnerability(input: {filter:{priority:{eq:"Priority 4"}},set:{priorityInt:4}}) {
		numUids
	}
}
`

func UpdateVulnerabilityPriority4(
	ctx_ context.Context,
	client_ graphql.Client,
) (*UpdateVulnerabilityPriority4Response, error) {
	req_ := &graphql.Request{
		OpName: "UpdateVulnerabilityPriority4",
		Query:  UpdateVulnerabilityPriority4_Operation,
	}
	var err_ error

	var data_ UpdateVulnerabilityPriority4Response
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}
