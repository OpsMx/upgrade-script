package september2024october2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func updateComponent(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----updating component analysis required field--------")

	ctx := context.Background()

	_, err := updateComponentAnalysisRequired(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in updating analysis_required field of component: %s", err.Error())
	}

	logger.Sl.Debugf("-----updated component analysis required field--------")

	return nil
}
