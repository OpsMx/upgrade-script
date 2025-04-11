package february2025march2025

import (
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func deletePolicies(prodDgraphClient graphql.Client) error {
	logger.Logger.Info("--------------Beginning to perform step: deletePolicies------------------")

	logger.Logger.Info("--------------Completed step: deletePolicies------------------")
	return nil
}
