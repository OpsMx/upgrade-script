package september2024october2024

import (
	"context"
	"fmt"
	"time"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
	"github.com/google/uuid"
)

func migrateBuildToSourceNode(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----migrating Build tool fields To Source tool--------")

	ctx := context.Background()

	resp, err := queryTransferableBuildToolFields(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in getting build tool fields to transfer i.e digest, build_digest, artifact_node: %s", err.Error())
	}

	if resp == nil || len(resp.QueryBuildTool) == 0 {
		logger.Sl.Debugf("No record for build tools")
		return nil
	}

	logger.Sl.Debugf("The total number of build tools records: %v", len(resp.QueryBuildTool))

	type scanDataUpdate struct {
		id               string
		digest           string
		buildDigest      string
		artifactNodeID   string
		sourceCodeToolID *string
	}

	scanDataUpdates := make([]scanDataUpdate, 0, len(resp.QueryBuildTool))

	for _, eachBuildTool := range resp.QueryBuildTool {
		if eachBuildTool != nil {

			if eachBuildTool.ArtifactNode == nil {
				continue
			}

			temp := scanDataUpdate{
				id:             eachBuildTool.Id,
				digest:         eachBuildTool.Digest,
				buildDigest:    eachBuildTool.BuildDigest,
				artifactNodeID: eachBuildTool.ArtifactNode.Id,
			}

			if len(eachBuildTool.SourceCodeTool) != 0 {
				temp.sourceCodeToolID = &eachBuildTool.SourceCodeTool[0].Id
			}

			scanDataUpdates = append(scanDataUpdates, temp)
		}
	}

	remainingScanDataUpdates := make([]scanDataUpdate, 0, len(resp.QueryBuildTool))

	for _, value := range scanDataUpdates {

		if value.sourceCodeToolID != nil {
			if _, err := updateSourceCodeToolFields(ctx, gqlClient, value.digest, value.buildDigest, value.artifactNodeID, *value.sourceCodeToolID); err != nil {
				return fmt.Errorf("error in updating the digest builddigest and artifact_node in source_code_tool id %s : %s", *value.sourceCodeToolID, err.Error())
			}
			continue
		}

		remainingScanDataUpdates = append(remainingScanDataUpdates, value)

	}

	var sourceCodeToolArr []*AddSourceCodeToolInput
	for _, value := range remainingScanDataUpdates {

		currTime := time.Now()
		input := &AddSourceCodeToolInput{
			Id:          uuid.NewString(),
			CreatedAt:   &currTime,
			Digest:      value.digest,
			BuildDigest: value.buildDigest,
			BuildTool: &BuildToolRef{
				Id: value.id,
			},
			ArtifactNode: &ArtifactRef{
				Id: value.artifactNodeID,
			},
		}

		sourceCodeToolArr = append(sourceCodeToolArr, input)

	}

	if len(sourceCodeToolArr) != 0 {
		if _, err := addSourceCodeTool(ctx, gqlClient, sourceCodeToolArr); err != nil {
			return fmt.Errorf("error in adding source_code_tool : %s", err.Error())
		}
	}

	logger.Sl.Debugf("-----migrated Build Tool To Source Code Tool--------")

	return nil
}
