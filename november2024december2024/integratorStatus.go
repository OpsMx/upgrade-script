package november2024december2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func updateIntegratorStatus(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----updating integrator status from disabled to non-connected--------")

	ctx := context.Background()

	_, err := UpdateIntegratorNotConnectedStatus(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in updating status of integrator from disabled to non-connected: %s", err.Error())
	}

	logger.Sl.Debugf("-----updated integrator status from disabled to non-connected--------")

	return nil
}
