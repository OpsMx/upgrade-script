package august2024august2024v2

import "time"

const (
	RunHistoryStatusException = "exception"

	Pass     string = "pass"
	Fail     string = "fail"
	Low      string = "low"
	Medium   string = "medium"
	High     string = "high"
	Critical string = "critical"

	SOURCE    string = "source"
	BUILD     string = "build"
	ARTIFACT  string = "artifact"
	DEPLOY    string = "deploy"
	ImageRisk string = "imageRisk"

	HighStatusValue int = 50
	LowStatusValue  int = 70
)

type Scoring struct {
	OrganizationName             string
	TeamName                     string
	Namespace                    string
	ClusterId                    string
	ApplicationName              string
	ServiceName                  string
	DeployedAt                   time.Time
	Policy                       map[string][]PolicyDetail
	Image                        string
	ImageTag                     string
	ImageSha                     string
	ApplicationDeploymentId      string
	BlockedDeployment            bool
	FailDeploymentFirewallResult bool
	DeploymentFirewall           bool
}

type PolicyDetail struct {
	PolicyName string
	Stage      string
	Status     string
	Severity   string
}

type PolicyStatusCount struct {
	PassCount         int
	LowPassCount      int
	MediumPassCount   int
	HighPassCount     int
	CriticalPassCount int
	LowCount          int
	MediumCount       int
	HighCount         int
	CriticalCount     int
}
