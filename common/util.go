package common

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
)

func shouldUpdateFeatTable() (bool, error) {

	schema, err := graphqlfunc.RetrieveSchema(Conf.ProdGraphQLAddr)
	if err != nil {
		return false, fmt.Errorf("StartUpgrade: %s", err.Error())
	}

	schemaVersion := getTheSchemaVersion(schema)

	logger.Sl.Infof("Current Schema After Dgraph Update: %s", schemaVersion.NameOfSchema())

	if schemaVersion < 4 { //if schema is before july 2024
		return true, nil
	}
	logger.Sl.Info("Schema Version After July No Update Needed for feat table")
	return false, nil
}

func shouldUpdatePolicies() (bool, error) {
	schema, err := graphqlfunc.RetrieveSchema(Conf.ProdGraphQLAddr)
	if err != nil {
		return false, fmt.Errorf("StartUpgrade: %s", err.Error())
	}

	schemaVersion := getTheSchemaVersion(schema)

	logger.Sl.Infof("Current Schema After Dgraph Update: %s", schemaVersion.NameOfSchema())

	if schemaVersion < 13 { //if schema is before march 2025
		return true, nil
	}

	logger.Sl.Info("Schema Version After Feb 2025, No Update Needed for policies")

	return false, nil
}
