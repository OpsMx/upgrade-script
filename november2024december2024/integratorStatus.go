package november2024december2024

import (
	"context"
	"fmt"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func updateIntegratorMetadata(gqlClient graphql.Client) error {

	logger.Sl.Debugf("-----updating integrator status from disabled to non-connected--------")

	ctx := context.Background()

	_, err := UpdateIntegratorNotConnectedStatus(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in updating status of integrator from disabled to non-connected: %s", err.Error())
	}

	logger.Sl.Debugf("-----updated integrator status from disabled to non-connected--------")

	logger.Sl.Debugf("-----updating integrator config status as active where the status was null or empty string previously--------")

	_, err = UpdateIntegratorConfigStatusAsActive(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in updating integrator config status as active where the status was null or empty string previously: %s", err.Error())
	}

	logger.Sl.Debugf("-----updated integrator config status as active where the status was null or empty string previously--------")

	logger.Sl.Debugf("-----updating integrator config key feat as false where the feat value was null previously--------")

	_, err = UpdateIntegratorKeyValueFeatFalse(ctx, gqlClient)
	if err != nil {
		return fmt.Errorf("error in updating integrator config key feat as false where the feat value was null previously: %s", err.Error())
	}

	logger.Sl.Debugf("-----updated integrator config key feat as false where the feat value was null previously--------")

	return nil
}
