package february2025march2025

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func AddDeploymentDetailsToRunHistory(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----updating new deployment fields in run history--------")

	ctx := context.Background()

	res, err := QueryRunHistoryWithApplicationDeployment(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in QueryRunHistoryWithApplicationDeployment: %s", err.Error())
	}

	logger.Sl.Debugf("records found for existing run history with application deployment: %d", len(res.QueryRunHistory))

	if len(res.QueryRunHistory) == 0 {
		logger.Sl.Debug("-----no record found for run history where application deployment exists--------")
		return nil
	}

	deploymentIDUpdate := make(map[string][]*string)
	sbomUpdate := make(map[string][]*string)
	nsUpdate := make(map[string][]*string)
	accountUpdate := make(map[string][]*string)
	clusterUpdate := make(map[string][]*string)
	appUpdate := make(map[string][]*string)
	teamIDUpdate := make(map[string][]*string)

	for _, val := range res.QueryRunHistory {

		if val.Id == nil {
			continue
		}

		deploymentIDUpdate[val.ApplicationDeployment.Id] = append(deploymentIDUpdate[val.ApplicationDeployment.Id], val.Id)
		sbomUpdate[val.ApplicationDeployment.ToolsUsed.Sbom] = append(sbomUpdate[val.ApplicationDeployment.ToolsUsed.Sbom], val.Id)
		nsUpdate[val.ApplicationDeployment.ApplicationEnvironment.Namespace] = append(nsUpdate[val.ApplicationDeployment.ApplicationEnvironment.Namespace], val.Id)
		accountUpdate[val.ApplicationDeployment.ApplicationEnvironment.Environment.Purpose] = append(accountUpdate[val.ApplicationDeployment.ApplicationEnvironment.Environment.Purpose], val.Id)
		clusterUpdate[val.ApplicationDeployment.ApplicationEnvironment.DeploymentTarget.Name] = append(clusterUpdate[val.ApplicationDeployment.ApplicationEnvironment.DeploymentTarget.Name], val.Id)
		appUpdate[val.ApplicationDeployment.ApplicationEnvironment.Application.Name] = append(appUpdate[val.ApplicationDeployment.ApplicationEnvironment.Application.Name], val.Id)
		teamIDUpdate[val.ApplicationDeployment.ApplicationEnvironment.Application.Team.Id] = append(teamIDUpdate[val.ApplicationDeployment.ApplicationEnvironment.Application.Team.Id], val.Id)

	}

	const batchSize = 10000

	logger.Sl.Debug("-----updating records of run history with application deployment ID--------")
	for key, val := range deploymentIDUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWAppDeploymentID(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWAppDeploymentID for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with application deployment ID--------")

	logger.Sl.Debug("-----updating records of run history with sbomTool--------")
	for key, val := range sbomUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWSbomTool(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWSbomTool for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with sbomTool--------")

	logger.Sl.Debug("-----updating records of run history with NS--------")
	for key, val := range nsUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWNamespace(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWNamespace for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with NS--------")

	logger.Sl.Debug("-----updating records of run history with Account--------")
	for key, val := range accountUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWAccount(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWAccount for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with Account--------")

	logger.Sl.Debug("-----updating records of run history with Cluster--------")
	for key, val := range clusterUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWCluster(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWCluster for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with Cluster--------")

	logger.Sl.Debug("-----updating records of run history with Applicaion Name--------")
	for key, val := range appUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWApplication(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWApplication for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with Applicaion Name--------")

	logger.Sl.Debug("-----updating records of run history with TeamID--------")
	for key, val := range teamIDUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWTeamID(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWTeamID for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with TeamID--------")
	logger.Sl.Debugf("-----updated new deployment fields in run history--------")

	return nil
}

func AddSbomToolToArtifactRunHistory(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----updating sbom field in artifact run history--------")

	ctx := context.Background()

	res, err := QueryRunHistoryWithArtifactScanData(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in QueryRunHistoryWithArtifactScanData: %s", err.Error())
	}

	logger.Sl.Debugf("records found for existing run history with artifactscan data: %d", len(res.QueryRunHistory))

	if len(res.QueryRunHistory) == 0 {
		logger.Sl.Debug("-----no record found for run history where artifactscan data exists--------")
		return nil
	}

	sbomUpdate := make(map[string][]*string)
	for _, val := range res.QueryRunHistory {

		if val.Id == nil {
			continue
		}
		sbomUpdate[val.ArtifactScan.Tool] = append(sbomUpdate[val.ArtifactScan.Tool], val.Id)
	}

	const batchSize = 10000

	logger.Sl.Debugf("-----updating sbom field in artifact run histories--------")
	for key, val := range sbomUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := i + batchSize
			if end > len(val) {
				end = len(val)
			}
			batch := val[i:end]

			if _, err := UpdateRunHistoryWSbomTool(ctx, gqlClient, batch, key); err != nil {
				return fmt.Errorf("error in UpdateRunHistoryWSbomTool for key %s: %w", key, err)
			}
		}
	}
	logger.Sl.Debugf("-----updated sbom field in artifact run histories--------")

	return nil
}
