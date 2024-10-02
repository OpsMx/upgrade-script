package august2024v2september2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func MigratePolicyEnfToSecurityIssues(gqlClient graphql.Client) error {

	return nil
}

func setForceApplyForGraphQL(gqlClient graphql.Client) error {

	ctx := context.Background()

	if _, err := UpdateForcePolicyForGraphqlTool(ctx, gqlClient); err != nil {
		return fmt.Errorf("error while updating forecpolicy field in policy enforcment for graphql tool: %s", err.Error())
	}
	return nil

}

func ingestArtifactNameTag(gqlClient graphql.Client) error {

	ctx := context.Background()

	resp, err := QueryArtifactNameAndTag(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in QueryArtifactNameAndTag while fetching records of artifact scan data: %s", err.Error())
	}

	if resp == nil {
		return nil
	}

	logger.Sl.Debugf("artifact scan data found in db", len(resp.QueryArtifactScanData))

	type scanDataUpdate struct {
		id      string
		nameTag string
	}

	nameTagArr := make([]scanDataUpdate, 0, len(resp.QueryArtifactScanData))
	for _, eachScanData := range resp.QueryArtifactScanData {
		nameTagArr = append(nameTagArr, scanDataUpdate{
			id:      eachScanData.Id,
			nameTag: fmt.Sprintf("%s:%s", eachScanData.ArtifactDetails.ArtifactName, eachScanData.ArtifactDetails.ArtifactTag),
		})
	}

	for _, value := range nameTagArr {
		if _, err := UpdateArtifactNameTag(ctx, gqlClient, value.id, value.nameTag); err != nil {
			return fmt.Errorf("error in updating the artifact name and tag in artifact scan data: %s", err.Error())
		}
	}

	return nil
}
