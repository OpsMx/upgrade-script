package august2024v2september2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func ingestArtifactNameTag(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----Ingesting ArtifactNameTag--------")

	ctx := context.Background()

	resp, err := QueryArtifactNameAndTag(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in QueryArtifactNameAndTag while fetching records of artifact scan data: %s", err.Error())
	}

	if resp == nil {
		logger.Sl.Debugf("No record for artifact name and tag within artifact scan data found in db")
		return nil
	}

	logger.Sl.Debugf("total record of artifact scan data found in db:", len(resp.QueryArtifactScanData))

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
			return fmt.Errorf("error in updating the artifact name and tag in artifact scan data id %s : %s", value.id, err.Error())
		}
	}

	logger.Sl.Debugf("-----Ingested ArtifactNameTag--------")

	return nil
}
