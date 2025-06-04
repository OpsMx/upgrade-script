package common

import (
	"fmt"
	"upgradationScript/schemas"
)

type SchemaOrder int

const (
	UnIdentifiedVersion SchemaOrder = iota
	April2024Version
	June2024Version
	June2024Version2
	July2024Version
	August2024Version
	August2024Version2
	September2024Version
	October2024Version
	November2024Version
	December2024Version
	January2025Version
	February2025Version
	March2025Version
	April2025Version
	May2025Version
)

var SchemasString = map[SchemaOrder]string{
	April2024Version:     schemas.April2024Schema,
	June2024Version:      schemas.June2024Schema,
	June2024Version2:     schemas.June2024Version2,
	July2024Version:      schemas.July2024Schema,
	August2024Version:    schemas.August2024Schema,
	August2024Version2:   schemas.August2024Version2,
	September2024Version: schemas.September2024Schema,
	October2024Version:   schemas.October2024Schema,
	November2024Version:  schemas.November2024Schema,
	December2024Version:  schemas.December2024Schema,
	January2025Version:   schemas.January2025Schema,
	February2025Version:  schemas.February2025Schema,
	March2025Version:     schemas.March2025Schema,
	April2025Version:     schemas.April2025Schema,
	May2025Version:       schemas.May2025Schema,
}

var schemaOrderMap = map[string]SchemaOrder{
	"April2024":     April2024Version,
	"June2024":      June2024Version,
	"June2024V2":    June2024Version2,
	"July2024":      July2024Version,
	"August2024":    August2024Version,
	"August2024V2":  August2024Version2,
	"September2024": September2024Version,
	"October2024":   October2024Version,
	"November2024":  November2024Version,
	"December2024":  December2024Version,
	"January2025":   January2025Version,
	"February2025":  February2025Version,
	"March2025":     March2025Version,
	"April2025":     April2025Version,
	"May2025":       May2025Version,
}

var expDgraphSchemaMap = map[int]bool{
	April2024Version.Int():     false,
	June2024Version.Int():      true,
	June2024Version2.Int():     false,
	July2024Version.Int():      true,
	August2024Version.Int():    true,
	August2024Version2.Int():   false,
	September2024Version.Int(): false,
	October2024Version.Int():   false,
	November2024Version.Int():  false,
	December2024Version.Int():  false,
	January2025Version.Int():   false,
	February2025Version.Int():  false,
	March2025Version.Int():     false,
	April2025Version.Int():     false,
}

func (e SchemaOrder) NameOfSchema() string {
	for name, schemaOrder := range schemaOrderMap {
		if e == schemaOrder {
			return name
		}
	}

	return "UnidentifiedSchema"
}

func (e SchemaOrder) String() string {
	return SchemasString[e]
}

func (e SchemaOrder) Int() int {
	return int(e)
}

func getTheSchemaVersion(checkSchema string) SchemaOrder {

	for schemaEnum, schema := range SchemasString {

		if schema == checkSchema {
			return schemaEnum
		}
	}

	return UnIdentifiedVersion
}

func checkIfSchemaAtUpgradedVersion(schemaOrder SchemaOrder) bool {
	return schemaOrder.Int() == UpgradeToVersion.Int()
}

func checkIfSchemaUpgradeNotPossible(schemaOrder SchemaOrder) bool {
	return schemaOrder.Int() > UpgradeToVersion.Int()
}

func totalUpgradeSteps(schemaVersion SchemaOrder) int {
	return UpgradeToVersion.Int() - schemaVersion.Int()
}

func upgradeSchemaBasedOnStep(schemaVersion SchemaOrder, step int) SchemaOrder {
	step += 1
	return SchemaOrder(schemaVersion.Int() + step)
}

func isExpDgraphRequired(currentVersionNum, upgradeToVersionNum int) (bool, error) {

	for i := currentVersionNum + 1; i <= upgradeToVersionNum; i++ {
		mapVal, keyExists := expDgraphSchemaMap[i]
		if !keyExists {
			return false, fmt.Errorf("couln't find schema verison in exp dgraph map iteration: %d", i)
		}
		if mapVal {
			return true, nil
		}
	}
	return false, nil
}
