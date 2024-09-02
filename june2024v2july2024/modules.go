package june2024v2july2024

type ConfigData struct {
	Data Data `yaml:"data"`
}

type Data struct {
	SSDIntegrationsYAML interface{} `yaml:"ssd-integrations.yaml"`
}

type SSDIntegrations struct {
	IntegrationData IntegrationStages `yaml:"integrationData"`
}

type IntegrationStage struct {
	Stage        string        `yaml:"stage"`
	Integrations []interface{} `yaml:"integrations"`
}

type IntegrationStages []IntegrationStage
