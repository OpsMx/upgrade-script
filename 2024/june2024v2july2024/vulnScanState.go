package june2024v2july2024

import (
	"context"
	"fmt"
	"upgradationScript/2024/june2024v2july2024/july2024"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func populateVulnerabilityScanState(prodDgraphClient graphql.Client) error {
	ctx := context.Background()

	logger.Logger.Debug("--------------Populating Vulnerability Scan State In Artifact Scan Data-----------------")

	_, err := july2024.UpdateVulnScanState(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: populateVulnerabilityScanStatus: UpdateVulnScanState: couldn't update vulnerability state in Artifcat Scan Data: %s", err.Error())
	}

	logger.Logger.Debug("---------------------------------------------")

	logger.Logger.Debug("--------------Completed Populating Vulnerability Scan State-----------------")

	return nil
}
