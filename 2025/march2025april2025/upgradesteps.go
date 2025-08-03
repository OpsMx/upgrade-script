package march2025april2025

import (
	"context"
	"fmt"
	"time"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

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

func UpgradeToApril2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToApril2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.April2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: UpdateSchema: %s", err.Error())
	}

	var artifactsResp *GetArtifactsResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		artifactsResp, err = GetArtifacts(ctx, prodDgraphClient)
		if err != nil {
			return fmt.Errorf("error getting artifacts response: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	deleteScanIDs := []string{}
	for _, eachartifact := range artifactsResp.Scanning {
		for _, eachScan := range eachartifact.ScanData {
			logger.Logger.Sugar().Infof("Delete ScanData for Artifact: %s", eachScan.ArtifactNameTag)
			deleteScanIDs = append(deleteScanIDs, eachScan.Id)
		}
	}

	for _, eachartifact := range artifactsResp.Noartifact {
		logger.Logger.Sugar().Infof("Delete ScanData for Artifact: %s", eachartifact.ArtifactNameTag)
		deleteScanIDs = append(deleteScanIDs, eachartifact.Id)
	}

	logger.Logger.Sugar().Infof("Number of Partially Scanned Artifacts %v", len(deleteScanIDs))

	batchSize := 50
	// Loop through deleteScanIDs in batches of 50
	for i := 0; i < len(deleteScanIDs); i += batchSize {
		// Calculate the end index for the current batch
		end := i + batchSize
		if end > len(deleteScanIDs) {
			end = len(deleteScanIDs)
		}

		// Create the current batch
		batch := deleteScanIDs[i:end]

		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			// Call the deletion function for the current batch
			if _, err := DeleteArtifactScanData(ctx, prodDgraphClient, batch); err != nil {
				return fmt.Errorf("couldn't delete artifact scan IDs %v. Error: %s", batch, err.Error()) // or handle the error appropriately (retry, continue, etc.)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	logger.Logger.Info("Deleted data of Partially Scanned Artifacts")

	var runHistoryResp *PolicyRunHistoryScanningDeploymentsResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		runHistoryResp, err = PolicyRunHistoryScanningDeployments(ctx, prodDgraphClient)
		if err != nil {
			return fmt.Errorf("couldnt retrieve runhistory ids error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	logger.Logger.Sugar().Infof("Number of deployments with corrupted data to be removed %v", len(runHistoryResp.QueryApplicationDeployment))

	deleteID := []*string{}
	for _, eachdeployment := range runHistoryResp.QueryApplicationDeployment {
		for _, eachrunhist := range eachdeployment.PolicyRunHistory {
			deleteID = append(deleteID, eachrunhist.Id)
			if len(deleteID) == 50 {
				if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
					if _, err := DeleteRunHistory(ctx, prodDgraphClient, deleteID); err != nil {
						return fmt.Errorf("couldnt delete runhistory id %s error: %s", *eachrunhist.Id, err.Error())
					}
					return nil
				}); err != nil {
					return err
				}

				deleteID = []*string{}
			}
		}
	}
	// Delete any remaining IDs that didn't fill a full batch
	if len(deleteID) > 0 {
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			if _, err := DeleteRunHistory(ctx, prodDgraphClient, deleteID); err != nil {
				return fmt.Errorf("couldn't delete remaining run history IDs, error: %s", err.Error())
			}
			return nil
		}); err != nil {
			return err
		}
	}

	logger.Logger.Sugar().Infof("Removed all corrupted data")

	logger.Logger.Sugar().Infof("set default values for new params of deployment & artifact table")

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		if _, err := SetDefaultAttemptForDeployment(ctx, prodDgraphClient); err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: SetDefaultAttemptForDeployment: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		if _, err := UpdateApplicationDeployment(ctx, prodDgraphClient); err != nil {
			return fmt.Errorf("couldnt update deployment from scanning err: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		if _, err := SetDefaultAttemptForArtifact(ctx, prodDgraphClient); err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: SetDefaultAttemptForArtifact: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		if _, err := SetDefaultScanStateForArtifact(ctx, prodDgraphClient); err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: SetDefaultScanStateForArtifact: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	logger.Logger.Sugar().Infof("default values for new params of deployment & artifact table are added")

	var runhistoriesResp *GetRunHistoriesResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		runhistoriesResp, err = GetRunHistories(ctx, prodDgraphClient)
		if err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: GetRunHistories: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	logger.Logger.Sugar().Infof("set default values for tools in runhistory")

	runHistoryIDs := []*string{}
	for _, runhistory := range runhistoriesResp.QueryRunHistory {
		runHistoryIDs = append(runHistoryIDs, runhistory.Id)
		if len(runHistoryIDs) == 1000 {
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := SetDefaultRunhistoryValues(ctx, prodDgraphClient, runHistoryIDs); err != nil {
					return fmt.Errorf("error: UpgradeToApril2025: SetDefaultRunhistoryValues: %s", err.Error())
				}
				return nil
			}); err != nil {
				return err
			}
			runHistoryIDs = []*string{}
		}
	}

	if len(runHistoryIDs) != 0 {
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			if _, err := SetDefaultRunhistoryValues(ctx, prodDgraphClient, runHistoryIDs); err != nil {
				return fmt.Errorf("error: UpgradeToApril2025: SetDefaultRunhistoryValues: %s", err.Error())
			}
			return nil
		}); err != nil {
			return err
		}
	}

	logger.Logger.Sugar().Infof("set default value for teamID in runhistory")

	var runHistories *QueryRunHistoryWTeamIDNullResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		runHistories, err = QueryRunHistoryWTeamIDNull(ctx, prodDgraphClient)
		if err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: QueryRunHistoryWTeamIDNull: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	runHistoryIDs = []*string{}
	for _, runhistory := range runHistories.QueryRunHistory {
		runHistoryIDs = append(runHistoryIDs, runhistory.Id)
		if len(runHistoryIDs) == 1000 {
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := SetDefaultTeamIDInRunHistory(ctx, prodDgraphClient, runHistoryIDs); err != nil {
					return fmt.Errorf("error: UpgradeToApril2025: SetDefaultTeamIDInRunHistory: %s", err.Error())
				}
				return nil
			}); err != nil {
				return err
			}
			runHistoryIDs = []*string{}
		}
	}

	if len(runHistoryIDs) != 0 {
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			if _, err := SetDefaultTeamIDInRunHistory(ctx, prodDgraphClient, runHistoryIDs); err != nil {
				return fmt.Errorf("error: UpgradeToApril2025: SetDefaultTeamIDInRunHistory: %s", err.Error())
			}
			return nil
		}); err != nil {
			return err
		}
	}

	logger.Logger.Sugar().Infof("remove addn policies to sync w repo")

	if err := SyncPoliciesWRepo(prodGraphUrl, prodToken); err != nil {
		return fmt.Errorf("UpgradeToApril2025: SyncPoliciesWRepo: error: %s", err.Error())
	}

	logger.Logger.Sugar().Infof("delete alerts for deleted policies")

	var runHistoriesToDelete *QueryAlertsToDeleteResponse
	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		var err error
		runHistoriesToDelete, err = QueryAlertsToDelete(ctx, prodDgraphClient)
		if err != nil {
			return fmt.Errorf("UpgradeToApril2025: QueryAlertsToDelete: error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	runHistoryIDs = []*string{}
	for _, runhistory := range runHistoriesToDelete.QueryRunHistory {
		runHistoryIDs = append(runHistoryIDs, runhistory.Id)
		if len(runHistoryIDs) == 1000 {
			if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
				if _, err := DeleteRunHistories(ctx, prodDgraphClient, runHistoryIDs); err != nil {
					return fmt.Errorf("error: UpgradeToApril2025: DeleteRunHistories: %s", err.Error())
				}
				return nil
			}); err != nil {
				return err
			}
			runHistoryIDs = []*string{}
		}
	}

	if len(runHistoryIDs) != 0 {
		if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
			if _, err := DeleteRunHistories(ctx, prodDgraphClient, runHistoryIDs); err != nil {
				return fmt.Errorf("error: UpgradeToApril2025: DeleteRunHistories: %s", err.Error())
			}
			return nil
		}); err != nil {
			return err
		}
	}

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		if _, err := CleanUpSecurityIssue(ctx, prodDgraphClient); err != nil {
			return fmt.Errorf("UpgradeToApril2025: CleanUpSecurityIssue error: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}

	logger.Logger.Info("--------------Completed UpgradeToApril2025------------------")

	return nil
}
