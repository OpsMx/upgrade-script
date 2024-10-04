package august2024v2september2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func populateBuildDetailsInArtifact(gqlClient graphql.Client) error {

	ctx := context.Background()

	resp, err := GetArtifactNameAndTag(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in GetArtifactNameAndTag while fetching records from artifact: %s", err.Error())
	}

	if resp == nil {
		logger.Sl.Debugf("No record for artifact name and tag within artifact node found in db")
		return nil
	}

	logger.Sl.Debugf("artifacts data found in db", len(resp.QueryArtifact))

	type artifactData struct {
		artifactId   string
		artifactName string
		artifactTag  string
	}

	artifactArr := make([]artifactData, 0, len(resp.QueryArtifact))
	for _, eachArtifact := range resp.QueryArtifact {
		artifactArr = append(artifactArr, artifactData{
			artifactId:   eachArtifact.Id,
			artifactName: eachArtifact.ArtifactName,
			artifactTag:  eachArtifact.ArtifactTag,
		})
	}

	type scanDataUpdate struct {
		artifactId  string
		buildToolId string
	}

	scanDataUpdates := make([]scanDataUpdate, 0, len(artifactArr))
	for _, eachArtifact := range artifactArr {

		resp, err := GetBuildToolId(ctx, gqlClient, eachArtifact.artifactName, eachArtifact.artifactTag)
		if err != nil {
			return fmt.Errorf("error in GetBuildToolId while fetching records from artifact: %s", err.Error())
		}

		if resp == nil {
			logger.Sl.Debugf("No record for build tool found in db for image %s:%s", eachArtifact.artifactName, eachArtifact.artifactTag)
			return nil
		}

		if len(resp.GetQueryBuildTool()) == 0 {
			logger.Sl.Debugf("build information is not yet available for image %s:%s", eachArtifact.artifactName, eachArtifact.artifactTag)
			return nil
		}

		scanDataUpdates = append(scanDataUpdates, scanDataUpdate{
			artifactId:  eachArtifact.artifactId,
			buildToolId: resp.QueryBuildTool[0].Id,
		})
	}

	for _, value := range scanDataUpdates {
		if _, err := PopulateArtifactBuildDetails(ctx, gqlClient, value.artifactId, value.buildToolId); err != nil {
			return fmt.Errorf("error in populating build details in artifact: %s", err.Error())
		}
	}

	return nil
}
