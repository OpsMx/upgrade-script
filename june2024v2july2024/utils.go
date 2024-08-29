package june2024v2july2024

func IsEncryptionRequired(configKey string) (isRequired bool) {

	switch configKey {
	case "token":
		isRequired = true
	case "password":
		isRequired = true
	case "awsAccessKey":
		isRequired = true
	case "awsSecretKey":
		isRequired = true
	case "key":
		isRequired = true
	default:
		isRequired = false
	}
	return isRequired
}

func getTranslatedScanName(scanName string) (newScanName string) {

	switch scanName {
	case "compliancescan":
		newScanName = "openssfcompliancescan"
	case "sastdastscan":
		newScanName = "sastsemgrepscan"
	case "licensescan":
		newScanName = "licensescanforcontainers"
	case "sastsonarscan":
		newScanName = "sonarqubeFileInsertion"
	default:
		newScanName = scanName
	}
	return newScanName
}

func getValue(scanName string) (value string) {

	switch scanName {
	case "sonarqubeFileInsertion":
		value = "inactive"
	case "vulnerabilityscan":
		value = "inactive"
	case "sastsnykscan":
		value = "Local Mode"
	case "sastsemgrepscan":
		value = "Local Mode"
	case "sastcodacyscan":
		value = "Local Mode"
	default:
		value = "active"
	}
	return value
}
