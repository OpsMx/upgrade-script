package common

import (
	"context"
	"fmt"
	"strings"

	"upgradationScript/april2024june2024"
	"upgradationScript/august2024august2024v2"
	"upgradationScript/august2024v2september2024"
	featuretable "upgradationScript/featureTable"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/july2024august2024"
	"upgradationScript/june2024june2024v2"
	"upgradationScript/june2024v2july2024"

	"upgradationScript/logger"
	policyingenstionscript "upgradationScript/policies"
)

func StartUpgrade() error {

	logger.Logger.Info("------------Starting Upgrade--------------------")

	logger.Logger.Info("------------Retrieve Schema from Prod Dgraph--------------------")

	schema, err := graphqlfunc.RetrieveSchema(Conf.ProdGraphQLAddr)
	if err != nil {
		return fmt.Errorf("StartUpgrade: %s", err.Error())
	}

	logger.Logger.Info("------------Retrieved Schema from Prod Dgraph--------------------")

	schemaVersion := getTheSchemaVersion(schema)

	logger.Sl.Infof("Current Schema: %s", schemaVersion.NameOfSchema())

	if schemaVersion == UnIdentifiedVersion && strings.TrimSpace(Conf.UpgradeFromVersion) == "" {
		return fmt.Errorf("schema version not identified")
	}

	if schemaVersion == UnIdentifiedVersion && Conf.UpgradeFromVersion != "" {
		logger.Logger.Info("---------------Could'nt Identify Schema version using the provided config------------------")
		schemaVersion = UpgradeFromVersion
	}

	if checkIfSchemaUpgradeNotPossible(schemaVersion) {
		return fmt.Errorf("cannot downgrade schema version. The current schema is at higher version than asked for")
	}

	if checkIfSchemaAtUpgradedVersion(schemaVersion) {
		logger.Logger.Info("---------------Schema already at upgraded version------------------------")
		return upgradePoliciesAndFeat()
	}

	logger.Logger.Info("------------All pre checks of schema passed starting with upgrading process--------------------")

	isSecondDgraphRequired, err := isExpDgraphRequired(schemaVersion.Int(), UpgradeToVersion.Int())
	if err != nil {
		return fmt.Errorf("isExpDgraphRequired: %s", err.Error())
	}

	if isSecondDgraphRequired {

		logger.Sl.Info("second dgraph setup is required. checking for connectivity")

		if err := allChecksForExpDgraph(schemaVersion); err != nil {
			return fmt.Errorf("allChecksForExpDgraph: cannot connect to second dgraph: %s", err.Error())
		}
		logger.Sl.Info("second dgraph is reachable & all checks passed")
	}

	for i := range totalUpgradeSteps(schemaVersion) {

		logger.Sl.Infof("STEP %d of upgrading schema", i)

		var isLastStep bool
		if i == totalUpgradeSteps(schemaVersion)-1 {
			isLastStep = true
		}

		if err := beginProcessOfUpgrade(upgradeSchemaBasedOnStep(schemaVersion, i), isSecondDgraphRequired, isLastStep); err != nil {
			return fmt.Errorf("StartUpgrade: beginProcessOfUpgrade: %s", err.Error())
		}

	}

	return upgradePoliciesAndFeat()

}

func beginProcessOfUpgrade(upgradeTo SchemaOrder, isSecondDgraphRequired, isLastStep bool) error {

	prodGraphqlClient := graphqlfunc.NewClient(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken)

	switch upgradeTo {
	case June2024Version:

		if err := allChecksForExpDgraph(June2024Version); err != nil {
			return err
		}

		expGraphqlClient := graphqlfunc.NewClient(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken)

		return april2024june2024.UpgradeToJune2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, Conf.ExpGraphQLAddr, Conf.RemoteDgraphRestoreUrl, prodGraphqlClient, expGraphqlClient)

	case June2024Version2:
		if isSecondDgraphRequired && !isLastStep {

			if err := allChecksForExpDgraph(June2024Version2); err != nil {
				return err
			}

			expGraphqlClient := graphqlfunc.NewClient(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken)

			return june2024june2024v2.UpgradeToJune2024V2(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken, expGraphqlClient)
		}
		return june2024june2024v2.UpgradeToJune2024V2(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case July2024Version:
		if err := allChecksForExpDgraph(July2024Version); err != nil {
			return err
		}

		expGraphqlClient := graphqlfunc.NewClient(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken)

		return june2024v2july2024.UpgradeToJuly2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, Conf.ExpGraphQLAddr, Conf.RemoteDgraphRestoreUrl, prodGraphqlClient, expGraphqlClient)

	case August2024Version:
		if err := allChecksForExpDgraph(August2024Version); err != nil {
			return err
		}

		expGraphqlClient := graphqlfunc.NewClient(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken)

		return july2024august2024.UpgradeToAugust2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, Conf.ExpGraphQLAddr, Conf.RemoteDgraphRestoreUrl, prodGraphqlClient, expGraphqlClient)

	case August2024Version2:
		if isSecondDgraphRequired && !isLastStep {

			if err := allChecksForExpDgraph(August2024Version2); err != nil {
				return err
			}

			expGraphqlClient := graphqlfunc.NewClient(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken)

			return august2024august2024v2.UpgradeToAugust2024v2(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken, expGraphqlClient)
		}
		return august2024august2024v2.UpgradeToAugust2024v2(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case September2024Version:
		if isSecondDgraphRequired && !isLastStep {

			if err := allChecksForExpDgraph(September2024Version); err != nil {
				return err
			}

			expGraphqlClient := graphqlfunc.NewClient(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken)

			return august2024v2september2024.UpgradeToSeptember2024(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken, expGraphqlClient)

		}
		return august2024v2september2024.UpgradeToSeptember2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	}

	logger.Sl.Debugf("no upgrade steps for %s", upgradeTo.NameOfSchema())
	return nil
}

func upgradePoliciesAndFeat() error {

	logger.Logger.Info("-----------Starting Upgrade of Policies & feat-----------------")

	graphqlClient := graphqlfunc.NewClient(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken)
	getOrgId, err := graphqlfunc.GetOrgId(context.Background(), graphqlClient)
	if err != nil {
		return fmt.Errorf("upgradePoliciesAndFeat: getOrgId: error: %s", err.Error())
	}

	orgId := getOrgId.QueryOrganization[0].Id

	if err := policyingenstionscript.UpgradePolicyAndTagData(graphqlClient, orgId); err != nil {
		return fmt.Errorf("upgradePoliciesAndFeat: %s", err.Error())
	}

	shouldUpdate, err := shouldUpdateFeatTable()
	if err != nil {
		return fmt.Errorf("upgradePoliciesAndFeat: %s", err.Error())
	}

	if shouldUpdate {
		if err := featuretable.FeatTableUpgradeSteps(graphqlClient, orgId); err != nil {
			return fmt.Errorf("upgradePoliciesAndFeat: FeatTableUpgradeSteps: error: %s", err.Error())
		}

		logger.Logger.Info("------------Completed Upgrade of Policies & feat--------------------")
	} else {
		logger.Logger.Info("------------Completed Upgrade of Policies--------------------")
	}

	logger.Logger.Info("------------Completed Upgrade--------------------")

	return nil
}
