// Code generated by github.com/Khan/genqlient, DO NOT EDIT.

package graphqlfunc

import (
	"context"

	"github.com/Khan/genqlient/graphql"
)

// GetOrgIdQueryOrganization includes the requested fields of the GraphQL type Organization.
type GetOrgIdQueryOrganization struct {
	// id is randomly assigned
	Id string `json:"id"`
}

// GetId returns GetOrgIdQueryOrganization.Id, and is useful for accessing the field via an interface.
func (v *GetOrgIdQueryOrganization) GetId() string { return v.Id }

// GetOrgIdResponse is returned by GetOrgId on success.
type GetOrgIdResponse struct {
	QueryOrganization []*GetOrgIdQueryOrganization `json:"queryOrganization"`
}

// GetQueryOrganization returns GetOrgIdResponse.QueryOrganization, and is useful for accessing the field via an interface.
func (v *GetOrgIdResponse) GetQueryOrganization() []*GetOrgIdQueryOrganization {
	return v.QueryOrganization
}

// The query or mutation executed by GetOrgId.
const GetOrgId_Operation = `
query GetOrgId {
	queryOrganization {
		id
	}
}
`

func GetOrgId(
	ctx_ context.Context,
	client_ graphql.Client,
) (*GetOrgIdResponse, error) {
	req_ := &graphql.Request{
		OpName: "GetOrgId",
		Query:  GetOrgId_Operation,
	}
	var err_ error

	var data_ GetOrgIdResponse
	resp_ := &graphql.Response{Data: &data_}

	err_ = client_.MakeRequest(
		ctx_,
		req_,
		resp_,
	)

	return &data_, err_
}
