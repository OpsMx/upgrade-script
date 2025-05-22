package march2025april2025

import (
	"context"
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToApril2025(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToApril2025------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.April2025Schema)); err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: UpdateSchema: %s", err.Error())
	}

	artifactsResp, err := GetArtifacts(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error getting artifacts response: %s", err.Error())
	}

	deleteScanIDs := []string{}
	for _, eachartifact := range artifactsResp.Scanning {
		for _, eachScan := range eachartifact.ScanData {
			logger.Logger.Sugar().Infof("Delete ScanData for Artifact: ", eachScan.ArtifactNameTag)
			deleteScanIDs = append(deleteScanIDs, eachScan.Id)
		}
	}

	for _, eachartifact := range artifactsResp.Noartifact {
		logger.Logger.Sugar().Infof("Delete ScanData for Artifact: ", eachartifact.ArtifactNameTag)
		deleteScanIDs = append(deleteScanIDs, eachartifact.Id)
	}

	logger.Logger.Sugar().Infof("Number of Partially Scanned Artifacts ", len(deleteScanIDs))

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

		// Call the deletion function for the current batch
		if _, err := DeleteArtifactScanData(context.Background(), prodDgraphClient, batch); err != nil {
			return fmt.Errorf("couldn't delete artifact scan IDs %v. Error: %s", batch, err.Error()) // or handle the error appropriately (retry, continue, etc.)
		}
	}

	logger.Logger.Info("Deleted data of Partially Scanned Artifacts")

	runHistoryResp, err := PolicyRunHistoryScanningDeployments(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("couldnt retrieve runhistory ids error: %s", err.Error())
	}

	logger.Logger.Sugar().Infof("Number of deployments with corrupted data to be removed", len(runHistoryResp.QueryApplicationDeployment))

	deleteID := []*string{}
	for _, eachdeployment := range runHistoryResp.QueryApplicationDeployment {
		for _, eachrunhist := range eachdeployment.PolicyRunHistory {
			deleteID = append(deleteID, eachrunhist.Id)
			if len(deleteID) == 50 {
				if _, err := DeleteRunHistory(context.Background(), prodDgraphClient, deleteID); err != nil {
					return fmt.Errorf("couldnt delete runhistory id %s error: %s", *eachrunhist.Id, err.Error())
				}
				deleteID = []*string{}
			}
		}
	}
	// Delete any remaining IDs that didn't fill a full batch
	if len(deleteID) > 0 {
		if _, err := DeleteRunHistory(context.Background(), prodDgraphClient, deleteID); err != nil {
			return fmt.Errorf("couldn't delete remaining run history IDs, error: %s", err.Error())
		}
	}

	logger.Logger.Sugar().Infof("Removed all corrupted data")

	if _, err := SetDefaultAttemptForDeployment(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: SetDefaultAttemptForDeployment: %s", err.Error())
	}

	if _, err := UpdateApplicationDeployment(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("couldnt update deployment from scanning err: %s", err.Error())
	}

	if _, err := SetDefaultAttemptForArtifact(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: SetDefaultAttemptForArtifact: %s", err.Error())
	}

	if _, err := SetDefaultScanStateForArtifact(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: SetDefaultScanStateForArtifact: %s", err.Error())
	}

	runhistoriesResp, err := GetRunHistories(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: GetRunHistories: %s", err.Error())
	}

	runHistoryIDs := []*string{}
	for _, runhistory := range runhistoriesResp.QueryRunHistory {
		runHistoryIDs = append(runHistoryIDs, runhistory.Id)
		if len(runHistoryIDs) == 1000 {
			if _, err := SetDefaultRunhistoryValues(context.Background(), prodDgraphClient, runHistoryIDs); err != nil {
				return fmt.Errorf("error: UpgradeToApril2025: SetDefaultRunhistoryValues: %s", err.Error())
			}
			runHistoryIDs = []*string{}
		}
	}

	if len(runHistoryIDs) != 0 {
		if _, err := SetDefaultRunhistoryValues(context.Background(), prodDgraphClient, runHistoryIDs); err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: SetDefaultRunhistoryValues: %s", err.Error())
		}
	}

	runHistories, err := QueryRunHistoryWTeamIDNull(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: UpgradeToApril2025: QueryRunHistoryWTeamIDNull: %s", err.Error())
	}
	runHistoryIDs = []*string{}
	for _, runhistory := range runHistories.QueryRunHistory {
		runHistoryIDs = append(runHistoryIDs, runhistory.Id)
		if len(runHistoryIDs) == 1000 {
			if _, err := SetDefaultTeamIDInRunHistory(context.Background(), prodDgraphClient, runHistoryIDs); err != nil {
				return fmt.Errorf("error: UpgradeToApril2025: SetDefaultTeamIDInRunHistory: %s", err.Error())
			}
			runHistoryIDs = []*string{}
		}
	}

	if len(runHistoryIDs) != 0 {
		if _, err := SetDefaultTeamIDInRunHistory(context.Background(), prodDgraphClient, runHistoryIDs); err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: SetDefaultTeamIDInRunHistory: %s", err.Error())
		}
	}

	if err := SyncPoliciesWRepo(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToApril2025: SyncPoliciesWRepo: error: %s", err.Error())
	}

	runHistoriesToDelete, err := QueryAlertsToDelete(context.Background(), prodDgraphClient)
	if err != nil {
		return fmt.Errorf("UpgradeToApril2025: QueryAlertsToDelete: error: %s", err.Error())
	}

	runHistoryIDs = []*string{}
	for _, runhistory := range runHistoriesToDelete.QueryRunHistory {
		runHistoryIDs = append(runHistoryIDs, runhistory.Id)
		if len(runHistoryIDs) == 1000 {
			if _, err := DeleteRunHistories(context.Background(), prodDgraphClient, runHistoryIDs); err != nil {
				return fmt.Errorf("error: UpgradeToApril2025: DeleteRunHistories: %s", err.Error())
			}
			runHistoryIDs = []*string{}
		}
	}

	if len(runHistoryIDs) != 0 {
		if _, err := DeleteRunHistories(context.Background(), prodDgraphClient, runHistoryIDs); err != nil {
			return fmt.Errorf("error: UpgradeToApril2025: DeleteRunHistories: %s", err.Error())
		}
	}

	if _, err := CleanUpSecurityIssue(context.Background(), prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToApril2025: CleanUpSecurityIssue error: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToApril2025------------------")

	return nil
}
