package july2024august2024

const (
	encryptionKeyPath = "/app/secrets/encryptionKey/AESEncryptionKey"
	JiraIssueApi      = "rest/api/2/issue"
)

type SecretData struct {
	Jira JiraIntegration `json:"jira,omitempty" yaml:"jira,omitempty"`
}

type JiraIntegration struct {
	Url        string `json:"url,omitempty" yaml:"url,omitempty"`
	Token      string `json:"token,omitempty" yaml:"token,omitempty"`
	Username   string `json:"username,omitempty" yaml:"username,omitempty"`
	ProjectKey string `json:"projectKey,omitempty" yaml:"projectKey,omitempty"`
	Field      string `json:"field,omitempty" yaml:"field,omitempty"`
	Value      string `json:"value,omitempty" yaml:"value,omitempty"`
}

type Integrator struct {
	Name     string
	Type     string
	Category string
	Data     map[string]interface{}
}

type JiraIssueDetails struct {
	Id     string `json:"id,omitempty" yaml:"id,omitempty"`
	Key    string `json:"key,omitempty" yaml:"key,omitempty"`
	Fields struct {
		Labels []string `json:"labels,omitempty" yaml:"labels,omitempty"`
		Status struct {
			Name string `json:"name,omitempty" yaml:"name,omitempty"`
		} `json:"status,omitempty" yaml:"status,omitempty"`
	} `json:"fields,omitempty" yaml:"fields,omitempty"`
}
