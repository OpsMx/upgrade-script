package february2025march2025

import (
	"context"
	"fmt"
	"time"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
	"github.com/cenkalti/backoff"
)

// callWithRetry will try your GraphQL operation up to MaxElapsedTime,
// backing off exponentially (with jitter) between attempts.
func callWithRetry(
	prodGraphUrl, prodToken string,
	operation func(ctx context.Context, gqlClient graphql.Client) error,
) error {
	// Configure an exponential backoff:
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 1 * time.Second
	exp.MaxInterval = 10 * time.Second
	exp.MaxElapsedTime = 10 * time.Minute

	attempt := 0
	// Wrap the operation so that each attempt has its own shorter timeout:
	retryOp := func() error {
		attempt++
		gqlient := graphqlfunc.NewClient(prodGraphUrl, prodToken)
		// each try gets, say, a 30s timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := operation(ctx, gqlient)
		if err != nil {
			logger.Sl.Warnf("Retry attempt %d failed: %v", attempt, err)
		}
		return err
	}

	return backoff.Retry(retryOp, exp)
}

func AddDeploymentDetailsToRunHistory(prodGraphUrl, prodToken string) error {

	logger.Sl.Debugf("-----updating new deployment fields in run history--------")

	var res *QueryRunHistoryWithApplicationDeploymentResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		res, err = QueryRunHistoryWithApplicationDeployment(ctx, gqlClient)
		if err != nil {
			return fmt.Errorf("error in QueryRunHistoryWithApplicationDeployment: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
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

	const batchSize = 2500

	logger.Sl.Debug("-----updating records of run history with application deployment ID--------")
	for key, val := range deploymentIDUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating application deployment ID %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				_, err := UpdateRunHistoryWAppDeploymentID(ctx, gqlClient, batch, key)
				if err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWAppDeploymentID for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with application deployment ID--------")

	logger.Sl.Debug("-----updating records of run history with sbomTool--------")
	for key, val := range sbomUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating sbom %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWSbomTool(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWSbomTool for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with sbomTool--------")

	logger.Sl.Debug("-----updating records of run history with NS--------")
	for key, val := range nsUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating ns %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWNamespace(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWNamespace for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with NS--------")

	logger.Sl.Debug("-----updating records of run history with Account--------")
	for key, val := range accountUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating account %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWAccount(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWAccount for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with Account--------")

	logger.Sl.Debug("-----updating records of run history with Cluster--------")
	for key, val := range clusterUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating cluster %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWCluster(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWCluster for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with Cluster--------")

	logger.Sl.Debug("-----updating records of run history with Applicaion Name--------")
	for key, val := range appUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating app name %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWApplication(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWApplication for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with Applicaion Name--------")

	logger.Sl.Debug("-----updating records of run history with TeamID--------")
	for key, val := range teamIDUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating teamID %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWTeamID(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWTeamID for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debug("-----updated records of run history with TeamID--------")
	logger.Sl.Debugf("-----updated new deployment fields in run history--------")

	return nil
}

func AddSbomToolToArtifactRunHistory(prodGraphUrl, prodToken string) error {

	logger.Sl.Debugf("-----updating sbom field in artifact run history--------")

	var res *QueryRunHistoryWithArtifactScanDataResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		res, err = QueryRunHistoryWithArtifactScanData(ctx, gqlClient)
		if err != nil {
			return fmt.Errorf("error in QueryRunHistoryWithArtifactScanData: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
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

	const batchSize = 2500

	logger.Sl.Debugf("-----updating sbom field in artifact run histories--------")
	for key, val := range sbomUpdate {
		for i := 0; i < len(val); i += batchSize {
			end := min(i+batchSize, len(val))
			batch := val[i:end]
			logger.Sl.Debugf("-----updating sbom %s to run history batch %v batchSize %v--------", key, i, len(batch))
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := UpdateRunHistoryWSbomTool(ctx, gqlClient, batch, key); err != nil {
					return fmt.Errorf("error in UpdateRunHistoryWSbomTool for key %s: %w", key, err)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	logger.Sl.Debugf("-----updated sbom field in artifact run histories--------")

	return nil
}
