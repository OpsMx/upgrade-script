package june2024v2july2024

func IsEncryptionRequired(configKey string) (isRequired bool) {

	switch configKey {
	case "token", "password", "awsAccessKey", "awsSecretKey", "key":
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
	case "sonarqubeFileInsertion", "vulnerabilityscan":
		value = "inactive"
	case "sastsnykscan", "sastsemgrepscan", "sastcodacyscan":
		value = "Local Mode"
	default:
		value = "active"
	}
	return value
}

func supportMultipleInsertion(integratorType string) (areSupported bool) {
	switch integratorType {
	case "jenkins", "docker", "quay", "ecr", "jfrog":
		areSupported = true
	default:
		areSupported = false
	}
	return areSupported
}
