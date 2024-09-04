package june2024v2july2024

type SSDIntegrations struct {
	IntegrationData IntegrationStages `yaml:"integrationData"`
}

type IntegrationStage struct {
	Stage        string        `yaml:"stage"`
	Integrations []interface{} `yaml:"integrations"`
}

type IntegrationStages []IntegrationStage
