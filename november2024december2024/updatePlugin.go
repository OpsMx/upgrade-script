package november2024december2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func updateArtifactTypeForPlugin(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----updating artifact type for plugin--------")

	ctx := context.Background()

	res, err := QueryAllBuildPlugins(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in getting build plugins artifact id: %s", err.Error())
	}

	if len(res.QueryBuildTool) == 0 && len(res.QueryBuildTool[0].BuildPlugins) == 0 {
		logger.Sl.Debugf("No record for build plugin artifact")
		return nil
	}

	artifactIDs := make([]string, 0, len(res.QueryBuildTool[0].BuildPlugins))

	for _, val := range res.QueryBuildTool[0].BuildPlugins {
		artifactIDs = append(artifactIDs, val.Id)
	}

	_, err = UpdateArtifactType(ctx, gqlClient, artifactIDs)
	if err != nil {
		return fmt.Errorf("error in updating artifact type for build plugins id: %s", err.Error())
	}

	logger.Sl.Debugf("-----updated artifact type for plugin--------")

	return nil
}