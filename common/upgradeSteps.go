package common

import (
	"context"
	"fmt"
	"strings"

	"upgradationScript/2024/april2024june2024"
	"upgradationScript/2024/august2024august2024v2"
	"upgradationScript/2024/august2024v2september2024"
	"upgradationScript/2024/july2024august2024"
	"upgradationScript/2024/june2024june2024v2"
	"upgradationScript/2024/june2024v2july2024"
	"upgradationScript/2024/november2024december2024"
	"upgradationScript/2024/october2024november2024"
	"upgradationScript/2024/september2024october2024"
	"upgradationScript/2025/december2024january2025"
	"upgradationScript/2025/february2025march2025"
	"upgradationScript/2025/january2025february2025"
	"upgradationScript/2025/march2025april2025"
	featuretable "upgradationScript/featureTable"
	graphqlfunc "upgradationScript/graphqlFunc"

	"upgradationScript/logger"
	policyingenstionscript "upgradationScript/policies"
)

func StartUpgrade() error {

	if Conf.UpdateOnlyPolicies {
		return upgradePoliciesAndFeat()
	}

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
		logger.Logger.Sugar().Infof("---------------Schema version defaulted to %s------------------", schemaVersion.NameOfSchema())
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
		logger.Sl.Info("Attempting to upgrade to schema ", upgradeSchemaBasedOnStep(schemaVersion, i).NameOfSchema())

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

			return june2024june2024v2.UpgradeToJune2024V2(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken, Conf.RemoteDgraphRestoreUrl, expGraphqlClient)
		}
		return june2024june2024v2.UpgradeToJune2024V2(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, "", prodGraphqlClient)

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

			return august2024august2024v2.UpgradeToAugust2024v2(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken, Conf.RemoteDgraphRestoreUrl, expGraphqlClient)
		}
		return august2024august2024v2.UpgradeToAugust2024v2(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, "", prodGraphqlClient)

	case September2024Version:

		return august2024v2september2024.UpgradeToSeptember2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case October2024Version:

		return september2024october2024.UpgradeToOctober2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case November2024Version:

		return october2024november2024.UpgradeToNovember2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case December2024Version:

		return november2024december2024.UpgradeToDecember2024(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case January2025Version:

		return december2024january2025.UpgradeToJanuary2025(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case February2025Version:

		return january2025february2025.UpgradeToFebruary2025(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case March2025Version:
		return february2025march2025.UpgradeToMarch2025(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)

	case April2025Version:
		return march2025april2025.UpgradeToApril2025(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken, prodGraphqlClient)
	}

	logger.Sl.Debugf("no upgrade steps for %s", upgradeTo.NameOfSchema())
	return nil
}

func upgradePoliciesAndFeat() error {

	logger.Logger.Info("-----------Starting Upgrade of Policies & feat-----------------")

	shouldUpdate, err := shouldUpdatePolicies()
	if err != nil {
		return fmt.Errorf("upgradePoliciesAndFeat: %s", err.Error())
	}

	if !shouldUpdate {
		logger.Logger.Info("------------Completed Upgrade--------------------")
		return nil
	}

	graphqlClient := graphqlfunc.NewClient(Conf.ProdGraphQLAddr, Conf.ProdDgraphToken)
	getOrgId, err := graphqlfunc.GetOrgId(context.Background(), graphqlClient)
	if err != nil {
		return fmt.Errorf("upgradePoliciesAndFeat: getOrgId: error: %s", err.Error())
	}

	orgId := getOrgId.QueryOrganization[0].Id

	if err := policyingenstionscript.UpgradePolicyAndTagData(graphqlClient, orgId); err != nil {
		return fmt.Errorf("upgradePoliciesAndFeat: %s", err.Error())
	}

	shouldUpdate, err = shouldUpdateFeatTable()
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
