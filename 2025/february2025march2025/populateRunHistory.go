package february2025march2025

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

type deploymentParamsToAdd struct {
	runHistoryID string
	deploymentID string
	sbomTool     string
	namespace    string
	account      string
	cluster      string
	application  string
	teamID       string
}

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

	var dataToUpdate []deploymentParamsToAdd
	for _, val := range res.QueryRunHistory {

		if val.Id == nil {
			continue
		}
		dataToUpdate = append(dataToUpdate, deploymentParamsToAdd{
			runHistoryID: *val.Id,
			deploymentID: val.ApplicationDeployment.Id,
			sbomTool:     val.ApplicationDeployment.ToolsUsed.Sbom,
			namespace:    val.ApplicationDeployment.ApplicationEnvironment.Namespace,
			account:      val.ApplicationDeployment.ApplicationEnvironment.Environment.Purpose,
			cluster:      val.ApplicationDeployment.ApplicationEnvironment.DeploymentTarget.Name,
			application:  val.ApplicationDeployment.ApplicationEnvironment.Application.Name,
			teamID:       val.ApplicationDeployment.ApplicationEnvironment.Application.Team.Id,
		})
	}

	for _, val := range dataToUpdate {
		_, err := UpdateRunHistoryDeploymentFields(ctx, gqlClient, &val.runHistoryID, val.deploymentID,
			val.sbomTool, val.namespace, val.account, val.cluster, val.application, val.teamID)
		if err != nil {
			return fmt.Errorf("error in UpdateRunHistoryDeploymentFields for run history id: %s, %s", val.runHistoryID, err.Error())
		}
	}

	return nil
}
