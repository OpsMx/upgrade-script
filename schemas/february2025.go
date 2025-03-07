package schemas

const February2025Schema = `type SchemaVersion {
    version: String!
}

interface RBAC {
    roles: [Role!]
}

enum RolePermission {
    admin
    write
    read
}

type Role {
    "id is randomly assigned"
    id: String! @id
    "group should be a URI format that includes a scope or realm"
    group: String! @search(by: [hash])
    permission: RolePermission! @search(by: [hash])
}

"""
KeyValue is a generic key/value pair, used as an attribute list or similar.
"""
type KeyValue {
    id: String! @id
    name: String! @search(by: [exact, regexp])
    value: String! @search(by: [exact, regexp])
    createdAt: DateTime! @search
}


type Organization implements RBAC
    @withSubscription
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryOrganization @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryOrganization @cascade { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryOrganization @cascade { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryOrganization @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryOrganization @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}"},
    ]},
    delete:
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
            )
{
    "id is randomly assigned"
    id: String! @id
    name: String! @search(by: [exact])
    roles: [Role!]
    teams: [Team!] @hasInverse(field: organization)
    environments: [DeploymentTarget!] @hasInverse(field: organization)
    policies: [PolicyDefinition!] @hasInverse(field: ownerOrg)
    policyEnforcements: [PolicyEnforcement!]
    integrators: [Integrator!] @hasInverse(field: organization)
    integratorConfigs: [IntegratorConfigs!] @hasInverse(field: organization)
    resources: [AbstractResource!] @hasInverse(field: organization)
    projects: [Project!] @hasInverse(field: organization)
}

"""
Environment can be things like dev, prod, staging etc.
"""
type Environment {
    id: String! @id
    organization: Organization!
    purpose: String! @search(by: [exact,regexp])
    integratorConfigs: [IntegratorConfigs!] @hasInverse(field: environment)
}

"""
DeploymentTarget describes a single place that things can be deployed into,
such as an AWS account or a Kubernetes cluster.
"""
type DeploymentTarget
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryDeploymentTarget @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryDeploymentTarget @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryDeploymentTarget @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryDeploymentTarget @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    delete:
            { rule: "{$type: {eq: \"internal-account/v1\"}}" }
            )
{
   "id is randomly assigned"
    id: String! @id
    name: String! @search(by: [exact, regexp])
    "this would be the ip/server address of the target environment"
    ip: String! @search(by: [exact])
    "expected value is kubernetes or non-kubernetes"
    targetType: String @search(by: [exact])
    "Options are: self-hosted(default), aws"
    hosting: String @search(by: [exact])
    "Account name from the cloud provider integrator is expected here"
    account: String @search(by: [exact])
    "this would be something like us-east-1 etc"
    region: String @search(by: [exact])
    kubescapeServiceConnected: String
    isFirewall: Boolean
    organization: Organization! @hasInverse(field: environments)
    defaultEnvironment: Environment!
}


type Team implements RBAC
    @withSubscription
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryTeam @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryTeam @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryTeam @cascade { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryTeam @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryTeam @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryTeam @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryTeam @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    delete:
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
    )
{
    "id is randomly assigned"
    id: String! @id
    name: String! @search(by: [exact])
    email: String @search(by: [exact,regexp])
    roles: [Role!]
    organization: Organization! @hasInverse(field: teams)
    applications: [Application!]
    labels: [KeyValue!]
    policies: [PolicyDefinition!] @hasInverse(field: ownerTeam)
    policyEnforcements: [PolicyEnforcement!]
    exceptions: [ExceptionAffects!] @hasInverse(field: affectsTeam)
    hasSecurityIssues: [SecurityIssueAffectsSummary!] @hasInverse(field: team)
    integratorConfigs: [IntegratorConfigs!] @hasInverse(field: team)
    AttachedJira: [Jira] @hasInverse(field: team)
    projects: [Project!] @hasInverse(field: team)
}

type Application implements RBAC
    @withSubscription
    @auth(
    query: {
        or: [
           { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryApplication @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryApplication @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryApplication @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}}"},
    ]},
    delete:
        { rule: "{$type: {eq: \"internal-account/v1\"}}" },
            )
{
    "id is randomly assigned"
    id: String! @id
    name: String! @search(by: [exact, regexp])
    roles: [Role!]
    environments: [ApplicationEnvironment!] @hasInverse(field: application)
    team: Team! @hasInverse(field: applications)
    policies: [PolicyDefinition!] @hasInverse(field: ownerApplication)
    policyEnforcements: [PolicyEnforcement!] @hasInverse(field: enforcedApplication)
    metadata: [KeyValue!]
    hasSecurityIssues: [SecurityIssueAffectsSummary!] @hasInverse(field: application)
}


"""
ApplicationEnvironment is a running instance of an application down to the level of a namespace or its non k8s equivalent.
"""
type ApplicationEnvironment @withSubscription {
    "id is randomly assigned"
    id: String! @id
    "environment denotes whether it is dev, prod, staging, non-prod etc"
    environment: Environment
    application: Application!
    deploymentTarget: DeploymentTarget!
    namespace: String! @search(by:[exact, regexp])
    "toolsUsed is a comma-separated string that contains all the tools(source, build, artifact, deploy etc) for an app env"
    toolsUsed: [String!]
    deployments: [ApplicationDeployment!] @hasInverse(field: applicationEnvironment)
    riskStatus: ApplicationRiskStatus @hasInverse(field: applicationEnvironment)
    metadata: [KeyValue!]
    hasSecurityIssues: [SecurityIssueAffectsSummary!] @hasInverse(field: applicationEnvironment)
    integratorConfigs: [IntegratorConfigs!] @hasInverse(field: applicationEnvironment)
}

"""
RiskStatus tells us what risk a current application instance or a deployment is at.
"""
enum RiskStatus {
    lowrisk
    mediumrisk
    highrisk
    apocalypserisk
    scanning
}

"""
ApplicationRiskStatus tells us about the risk status and alerts for different stages for an application environment.
"""
type ApplicationRiskStatus {
    id: ID!
    riskStatus: RiskStatus @search(by: [exact,regexp])
    sourceCodeAlerts: Int
    buildAlerts: Int
    artifactAlerts: Int
    deploymentAlerts: Int
    postDeploymentAlerts: Int
    createdAt: DateTime!
    updatedAt: DateTime!
    applicationEnvironment: ApplicationEnvironment!
}


"""
DeploymentStage is an enum denoting the stage of the deployment. .
"""
enum DeploymentStage {
    "deployment is discovered from the events"
    discovered
    "scanning is under process"
    scanning
    "deployment is known to have passed the deployment firewall and the deployment(ie the artifact) is live"
    current
    "deployment becomes a past deployment because another fresh deployment has happened"
    previous
    "deployment is blocked by the firewall"
    blocked
}

"""
ApplicationDeployment tells us about the the artifact deployed along with its associated details.
"""
type ApplicationDeployment {
    "id is randomly assigned"
    id: String! @id
    "platform will help us identify which image was actually deployed helping us identify the accurate sha"
    platform: String @search
    serviceUrl: String @search
    "artifact that is deployed"
    artifact: [Artifact!] @hasInverse(field: artifactDeployment)
    applicationEnvironment: ApplicationEnvironment!
    deployedAt: DateTime @search
    "deploymentStage is an enum and can be discovered, current, previous or blocked"
    deploymentStage: DeploymentStage! @search(by: [exact])
    "source is argo, spinnaker etc"
    source: String!
    "component would be a service"
    component: String! @search(by: [exact, regexp])
    "user who deployed the artifact"
    deployedBy: String
    "toolsUsed contains tools of different stages of source, build, artifact and deploy along with some different tools"
    toolsUsed: ToolsUsed!
    "deploymentRisk is the risk status of the deployment"
    deploymentRisk: ApplicationDeploymentRisk @hasInverse(field: applicationDeployment)
    "policyRunHistory is the policy execution history for this deployment"
    policyRunHistory: [RunHistory!] @hasInverse(field: applicationDeployment)
    deploymentTags: [KeyValue!]
    hasSecurityIssues: [SecurityIssueAffectsSummary!] @hasInverse(field: currentDeployed)
    utilizedResources: [AbstractResource] @hasInverse(field: applicationDeployments)
    isNetworkExploitable: Boolean
}

type ToolsUsed {
    id: ID!
    source: String
    build: String
    artifact: String
    deploy: String
    postdeploy: String
    sbom: String @search(by: [exact, regexp])
    misc: [String!]
}

"""
ApplicationDeploymentRisk tells us about the risk status and alerts for different stages for an application deployment.
"""
type ApplicationDeploymentRisk {
    id: ID!
    sourceCodeAlertsScore: Int
    buildAlertsScore: Int
    artifactAlertsScore: Int
    deploymentAlertsScore: Int
    postDeploymentAlertsScore: Int
    deploymentRiskStatus: RiskStatus @search(by: [exact,regexp])
    applicationDeployment: ApplicationDeployment! @hasInverse(field: deploymentRisk)
}


type Integrator
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    delete:
        { rule: "{$type: {eq: \"internal-account/v1\"}}" }
            )
{
    id: String! @id
    organization: Organization!
    type: String! @search(by: [exact])
    category: String! @search(by: [exact])
    status: String! @search(by: [exact])
    integratorConfigs: [IntegratorConfigs!]
    createdAt: DateTime!
    updatedAt: DateTime!
}

type IntegratorConfigs
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { integrator { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
        ]
    },
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { integrator { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
        ]
    },
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { integrator { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
        ]
    },
    delete: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { integrator { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryIntegratorConfigs @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
        ]
    })
{
    id: ID!
    name: String! @search(by: [exact])
    configs: [IntegratorKeyValues!]
    status: String! @search(by: [exact])
    integrator: Integrator! @hasInverse(field: integratorConfigs)
    organization: Organization@hasInverse(field: integratorConfigs)
    team: Team @hasInverse(field: integratorConfigs)
    environment: Environment @hasInverse(field: integratorConfigs)
    applicationEnvironment: ApplicationEnvironment @hasInverse(field: integratorConfigs)
    project: Project @hasInverse(field: integratorConfigs)
}

type IntegratorKeyValues {
    feat: Boolean! @search
    key: String! @search(by: [exact])
    value: String! @search(by: [exact])
    encrypt: Boolean!
}

"""
Tag tells us about the tags that are linked to policies and other components.
"""
type Tag {
    id: String! @id @search(by:[exact])
    tagName: String! @search(by:[exact])
    tagValue: String! @search(by:[exact,regexp])
    tagDescription: String
    createdBy: String @search(by:[exact])
    createdAt: DateTime!
    updatedAt: DateTime!
    policies: [PolicyEnforcement!] @hasInverse(field: tags)
}

type PolicyDefinition {
    id: String! @id
    ownerOrg: Organization!
    ownerTeam: Team
    ownerApplication: Application
    createdAt: DateTime!
    updatedAt: DateTime!
    policyName: String! @search(by: [exact,regexp])
    category: String! @search(by: [exact])
    stage: String! @search(by: [exact,regexp])
    description: String! @search(by: [exact])
    scheduledPolicy: Boolean! @search
    script: String! @search(by: [exact])
    variables: String @search(by: [exact])
    conditionName: String @search(by: [exact])
    suggestion: String @search(by: [exact])
}

type PolicyEnforcement {
    id: ID!
    policy: PolicyDefinition!
    #It should be either of the three or else if node is shared it will make changes to 2 different destination, how to enforce that?
    enforcedOrg: Organization @hasInverse(field: policyEnforcements)
    enforcedTeam: Team @hasInverse(field: policyEnforcements)
    enforcedApplication: Application @hasInverse(field: policyEnforcements)
    status: Boolean! @search
    forceApply: Boolean @search
    severity: Severity!
    datasourceTool: String! @search(by: [exact])
    action: String! @search(by: [exact])
    conditionValue: String @search(by: [exact])
    environments: [Environment!]
    tags: [Tag!] @hasInverse(field: policies)
    createdAt: DateTime!
    updatedAt: DateTime!
}

type Jira {
    id: ID!
    jiraId: String! @search(by: [exact, regexp])
    url: String!
    status: String! @search(by: [exact, regexp])
    assignee: String @search(by: [exact, regexp])
    createdAt: DateTime!
    updatedAt: DateTime!
    affectsIndividualComponent: [RunHistory!] @hasInverse(field: AttachedJira)
    affectsSecurityissue: SecurityIssue @hasInverse(field: AttachedJira)
    team: Team @hasInverse(field: AttachedJira)
}

type RunHistory  {
    id: ID!
    policyId: String! @search(by: [exact])
    applicationDeployment: ApplicationDeployment @hasInverse(field: policyRunHistory)
    artifactScan: ArtifactScanData @hasInverse(field: artifactRunHistory)
    PolicyName: String! @search(by: [exact,regexp])
    Stage: String! @search(by: [exact,regexp])
    Artifact: String! @search(by: [exact])
    ArtifactTag: String! @search(by: [exact])
    ArtifactSha: String! @search(by: [exact,regexp])
    ArtifactNameTag: String! @search(by: [exact,regexp])
    DatasourceTool: String! @search(by: [exact,regexp])
    CreatedAt: DateTime! @search
    UpdatedAt: DateTime! @search
    DeployedAt: DateTime! @search
    Hash: String
    Pass: Boolean! @search
    EvalData: PolicyEvaluationData @hasInverse(field: affects)
    FileApi: String
    AttachedJira: Jira @hasInverse(field: affectsIndividualComponent)
    Status: String! @search(by: [exact])
    exception: ExceptionAffects @hasInverse(field: runHistories)
    scheduledPolicy: Boolean! @search
    policyEnforcements: PolicyEnforcement!
    securityIssue: SecurityIssue @hasInverse(field: Affects)
}

type PolicyEvaluationData {
    """data Type is gonna help us identify if a DB record is used to evaluate or a json
   current scope json is for generic policies & vuln policies will attach VulnNode -> pending redis data & other inprogram policies"""   
    Id: ID!
    dataType: String! @search(by: [exact])
    rawData: String
    vulnNode: Vulnerability @hasInverse(field: policyEvaluation)
    enrichedAffectedResources: [EnrichedFinding!] @hasInverse(field: finding) 
    affects:RunHistory! @hasInverse(field: EvalData)
    checkedResources: Int
    affectedResources: Int
}

type SecurityIssue {
    id: ID!
    AlertTitle: String @search(by: [exact,regexp])
    AlertMessage: String @search(by: [exact])
    Suggestions: String @search(by: [exact])
    Severity: Severity! @search(by: [exact,regexp])
    SeverityInt: Int! @search
    CreatedAt: DateTime! @search
    UpdatedAt: DateTime! @search
    Action: String! @search(by: [exact,regexp])
    Reason: String @search(by: [exact])
    Error: String @search(by: [exact])
    policyEnforcements: PolicyEnforcement!
    AttachedJira: [Jira] @hasInverse(field: affectsSecurityissue)
    Affects: [RunHistory!] @hasInverse(field: securityIssue)
    Summary: [SecurityIssueAffectsSummary!] @hasInverse(field: securityIssue)
}

type SecurityIssueAffectsSummary {
    id: ID!
    "only pre-deployment analysis or deployment analysis"
    type: String! @search(by: [exact])
    team: Team @hasInverse(field: hasSecurityIssues)
    application: Application @hasInverse(field: hasSecurityIssues)
    applicationEnvironment: ApplicationEnvironment @hasInverse(field: hasSecurityIssues)
    service: String  @search(by: [exact,regexp])
    currentDeployed: ApplicationDeployment @hasInverse(field: hasSecurityIssues)
    artifactScanTS: [ArtifactScanDataTS!] @hasInverse(field: summary)
    exception: ExceptionAffects @hasInverse(field: hasSecurityIssues)
    securityIssue: SecurityIssue! @hasInverse(field: Summary)
}

type ArtifactScanDataTS {
    id: ID!
    artifact: ArtifactScanData! @hasInverse(field: artifactScanTS)
    timestamps: [DateTime!] @search 
    summary: [SecurityIssueAffectsSummary!] @hasInverse(field: artifactScanTS)   
}

"""
BuildTool contains data from build tool events.
"""
type BuildTool {
    "id is randomly assigned"
    id: String! @id
    "buildId is a unique job id, run id for a job/pipeline/action"
    buildId: String! @search(by: [exact,regexp])
    "tool is jenkins etc"
    tool: String! @search(by: [exact])
    "buildName is the name of the job/pipeline/action"
    buildName: String! @search(by: [exact, regexp])
    buildUrl: String! @search(by: [exact,  regexp])
    "buildTime is the time at which the artifact was built"
    buildTime: DateTime
    "buildUser is the user that built the artifact"
    buildUser: String
    "plugins used at the build time"
    buildPlugins:[Artifact!] @hasInverse(field: plugins)
    "sourceCodeTool links a BuildTool node to the source details"
    sourceCodeTool: [SourceCodeTool!] @hasInverse(field: buildTool)
    "commitMetaData links a BuildTool node to the git commit based details"
    commitMetaData: [CommitMetaData!] @hasInverse(field: buildTool)
    createdAt: DateTime!
}

"""
SourceCodeTool contains the source details about the artifact that was built.
"""
type SourceCodeTool {
    "id is randomly assigned"
    id: String! @id
    createdAt: DateTime!
    "scm is the scm tool github/gitlab etc"
    scm: String!
    "repository is the git remote repository"
    repository: String! @search(by: [exact,regexp])
    "branch is the git branch on which the artifact was built"
    branch: String!
    "headCommit is the checkout out head commit"
    headCommit: String
    "diffCommits is a comma separated string of the commits between the previous built artifact and the current"
    diffCommits: String
    licenseName: String
    visibility: String
    workflowName: String
    "parentRepo is populated in case the git repo is a fork"
    parentRepo: String
    buildTool: BuildTool!
    sourceCodePath: String
    sonarqubeProjectKey: String
    "artifactNode links a Source node to an artifact"
    artifactNode: Artifact @hasInverse(field: sourceDetails)
    "digest is the sha of the artifact"
    digest: String! @search(by: [exact])
    "buildDigest is the sha of the artifact as sent from the build tool"
    buildDigest: String @search(by: [exact])
}

"""
CommitMetaData contains the git commit related details of the source repository .
"""
type CommitMetaData {
    "id is randomly assigned"
    id: ID!
    "commit is a git commit that was used to build an artifact"
    commit: String
    repository: String
    "commitSign tells us whether the commit is signed"
    commitSign: Boolean
    noOfReviewersConf: Int
    reviewerList: [String!]
    approverList: [String!]
    buildTool: BuildTool! @hasInverse(field: commitMetaData)
}

type Artifact {
    id: String! @id
    artifactType: String! @search(by: [exact])
    artifactName: String! @search(by: [exact, regexp])
    artifactTag: String! @search(by: [exact, regexp])
    artifactSha: String! @search(by: [exact])
    scanData: [ArtifactScanData!]
    artifactDeployment: [ApplicationDeployment!] @hasInverse(field: artifact)
    sourceDetails: SourceCodeTool @hasInverse(field: artifactNode)
    plugins: [BuildTool!] @hasInverse(field: buildPlugins)
}


interface Scan{
    id: String! @id
    status: String @search(by:[exact])
    detailedStatus: String
    category: String @search(by: [exact,regexp])
    createdAt: DateTime @search
    updatedAt: DateTime @search
}

type ArtifactScanData {
    id: String! @id
    "platform: String! @search(by: [exact]) -> add later"
    artifactSha: String! @search(by: [exact])
    artifactNameTag: String! @search(by: [exact,regexp])
    tool: String! @search(by: [exact])
    artifactDetails: Artifact @hasInverse(field: scanData)
    lastScannedAt: DateTime
    createdAt: DateTime @search
    vulnTrackingId: String
    vulnScanState: String @search(by: [exact])
    components: [Component!]
    vulnCriticalCount: Int @search
    vulnHighCount: Int @search
    vulnMediumCount: Int @search
    vulnLowCount: Int @search
    vulnInfoCount: Int @search
    vulnUnknownCount: Int @search
    vulnNoneCount: Int @search
    vulnTotalCount: Int @search
    scanFile: [ScanFileResult!] 
    artifactRisk: ArtifactRisk @hasInverse(field: artifactScanResult)
    artifactRunHistory: [RunHistory!] @hasInverse(field: artifactScan)
    artifactTags: [KeyValue!]
    artifactScanTS: [ArtifactScanDataTS!] @hasInverse(field: artifact)
}

type ArtifactRisk {
    id: ID!
    sourceCodeAlertsScore: Int
    buildAlertsScore: Int
    artifactAlertsScore: Int
    deploymentAlertsScore: Int
    artifactRiskStatus: RiskStatus @search(by: [exact,regexp])
    artifactScanResult: ArtifactScanData! @hasInverse(field: artifactRisk)
}

type ScanFileResult {
    id: ID!
    name: String! @search(by: [exact, regexp])
    url: String!
}

type Component {
    id: String! @id
    type: String!
    name: String! @search(by: [exact, regexp])
    version: String! @search(by: [exact, regexp])
    licenses: [String!]
    purl: String @search(by: [exact])
    cpe: String @search(by: [exact])
    scannedAt: DateTime
    analysisRequired: Boolean @search
    analysis: ComponentAnalysis @hasInverse(field: Components)
    vulnerabilities: [Vulnerability!] @hasInverse(field: affects)
    artifacts: [ArtifactScanData!] @hasInverse(field: components)
}

type ComponentAnalysis {
    Id: ID!
    Name: String! @search(by: [exact,regexp])
    Components:[Component!] @hasInverse(field: analysis)
    Severity: Severity @search(by: [exact,regexp])
    SeverityInt: Int @search
    Stars: Int @search
    Forks: Int @search
    Contributors: Int @search
    VulnCritical: Int @search
    VulnHigh: Int @search
    VulnMedium: Int @search
    VulnLow: Int @search
    VulnOthers: Int @search
    MeanTimeToRepair:  Int @search
    Licenses: [String!] @search(by: [exact,regexp])
    CreatedAt: DateTime
    ScannedAt: DateTime
    LastViewed: DateTime @search
}

type ComponentLicenses {
    Id: ID!
    Name: String! @search(by: [exact,regexp])
    Category: String! @search(by: [exact,regexp])
}

enum Severity {
    apocalypse
    critical
    high
    medium
    low
    info
    none
    unknown
}

type Vulnerability {
    id: String! @id
    parent: String! @search(by: [exact, regexp])
    ratings: Severity @search(by: [exact])
    ratingsInt: Int @search
    cwes: [CWE!]
    summary: String
    detail: String
    recommendation: String
    published: DateTime
    modified: DateTime
    createdAt: DateTime @search
    cvss: Float @search
    attackVector: String @search(by:[exact])
    priority: String @search(by: [exact, regexp])
    priorityInt: Int @search
    epss: Float @search
    cisa_kev: String @search(by: [exact, regexp])
    exploitation: String @search(by: [exact, regexp])
    automatable: String @search(by: [exact, regexp])
    technicalImpact: String @search(by: [exact, regexp])
    affects: [Component!] @hasInverse(field: vulnerabilities)
    policyEvaluation: [PolicyEvaluationData!] @hasInverse(field: vulnNode)
}

type CWE {
    id: String! @id
    name: String!
    description: String
}

type Exception implements RBAC 
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryException @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryException @cascade { affects { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryException @cascade { affects { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write]}}) { __typename }}}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryException @cascade { affects { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write]}}) { __typename }}}}}"},
    ]},
    delete:{
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryException @cascade { affects { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write]}}) { __typename }}}}}"},
    ]}      
            )
{
    id: ID!
    type: String! @search(by: [exact, regexp])
    name: String! @search(by: [exact, regexp])
    affects: [ExceptionAffects!]
    createdAt: DateTime! @search
    updatedAt: DateTime! @search
}

type ExceptionAffects implements RBAC 
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryExceptionAffects @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryExceptionAffects @cascade { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryExceptionAffects @cascade { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryExceptionAffects @cascade { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write]}}) { __typename }}}}"},
    ]},
    delete:{
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryExceptionAffects @cascade { affectsTeam { roles(filter: {group: {in: $groups}, permission: {in: [admin,write]}}) { __typename }}}}"},
    ]}      
            )
{
    id: ID!
    createdBy: String! @search(by: [exact, regexp])
    affectsTeam: Team! @hasInverse(field: exceptions)
    affectsApplication: Application
    affectsServices: [String!] @search(by: [exact, regexp])
    validUpTo: DateTime! @search
    createdAt: DateTime! @search
    updatedAt: DateTime! @search
    reason: String! @search(by: [exact, regexp])
    status: String! @search(by: [exact, regexp])
    exception: Exception! @hasInverse(field: affects)
    runHistories: [RunHistory!] @hasInverse(field: exception)
    hasSecurityIssues: [SecurityIssueAffectsSummary!] @hasInverse(field: exception)
}


interface AbstractResource{
    id: String! @id 
    organization: Organization! @hasInverse(field: resources)
    cloudAccountName: String! @search(by: [exact])
    cloudProvider: String!  @search(by: [exact])
    resourceId: String  @search(by: [exact, regexp])
    name: String  @search(by: [exact, regexp])
    resourceType: String  @search(by: [exact, regexp])
    childResources: [AbstractResource!] @hasInverse(field: parentResource)
    parentResource: AbstractResource @hasInverse(field: childResources)
    associatedResources: [AbstractResource!] @hasInverse(field: associatedResources)
    enrichedFindings: [EnrichedFinding!] @hasInverse(field: affectedResource)
    applicationDeployments: [ApplicationDeployment!] @hasInverse(field: utilizedResources)
}

type CSPMResourceScanGroup implements AbstractResource @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryCSPMResourceScanGroup @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryCSPMResourceScanGroup @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryCSPMResourceScanGroup @cascade { organization { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryCSPMResourceScanGroup @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryCSPMResourceScanGroup @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
     delete:
        { rule: "{$type: {eq: \"internal-account/v1\"}}" },  
    )
    {
    id: String! @id 
    resourceId: String  @search(by: [exact, regexp])
    name: String  @search(by: [exact, regexp])
    organization: Organization! @hasInverse(field: resources)
    cloudAccountName: String! @search(by: [exact])
    cloudProvider: String!  @search(by: [exact])
    resourceType: String  @search(by: [exact, regexp])
    childResources: [AbstractResource!] @hasInverse(field: parentResource)
    parentResource: AbstractResource @hasInverse(field: childResources)
    associatedResources: [AbstractResource!] @hasInverse(field: associatedResources)
    cspmScan: CSPMScan! @hasInverse(field: associatedResourceScanGroup)
    enrichedFindings: [EnrichedFinding!] @hasInverse(field: affectedResource)
    applicationDeployments: [ApplicationDeployment!] @hasInverse(field: utilizedResources)
}

type NetworkResource implements AbstractResource @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryNetworkResource @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryNetworkResource @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryNetworkResource @cascade { organization { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryNetworkResource @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryNetworkResource @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
     delete:
        { rule: "{$type: {eq: \"internal-account/v1\"}}" },  
    )
    {
    id: String! @id 
    resourceId: String  @search(by: [exact, regexp])
    name: String  @search(by: [exact, regexp])
    organization: Organization! @hasInverse(field: resources)
    cloudAccountName: String! @search(by: [exact])
    cloudProvider: String!  @search(by: [exact])
    resourceType: String  @search(by: [exact, regexp])
    childResources: [AbstractResource!] @hasInverse(field: parentResource)
    parentResource: AbstractResource @hasInverse(field: childResources)
    associatedResources: [AbstractResource!] @hasInverse(field: associatedResources)
    details: String
    enrichedFindings: [EnrichedFinding!] @hasInverse(field: affectedResource)
    applicationDeployments: [ApplicationDeployment!] @hasInverse(field: utilizedResources)
    networkResourceType: String! @search(by: [exact, regexp]) #switch, router, firewall
    cidr: String @search(by: [exact, regexp])
    networkInterface: [NetworkResource!] @hasInverse(field: networkInterface)
    ingress: [FirewallRules!] #firewall
    egress: [FirewallRules!] #firewall
    routingTable: [Route!] #router/switch
}

type Route {
    source: [RouteEntry!]
    destination: [RouteEntry!]
}

interface NetworkEntry {
    portRange: [String!] @search(by: [exact, regexp])
    cidr: String! @search(by: [exact, regexp])
    protocol: String! @search(by: [exact,regexp])
    networkInterface: NetworkResource
}

type FirewallRules implements NetworkEntry{
    portRange: [String!] @search(by: [exact, regexp])
    cidr: String! @search(by: [exact, regexp])
    protocol: String! @search(by: [exact, regexp])
    networkInterface: NetworkResource
    access: String! @search(by: [exact, regexp]) #allow/deny
}

type RouteEntry implements NetworkEntry{
    portRange: [String!] @search(by: [exact, regexp])
    cidr: String! @search(by: [exact, regexp])
    protocol: String! @search(by: [exact, regexp])
    networkInterface: NetworkResource
    subnet: NetworkResource
}


type Resource implements AbstractResource @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryResource @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryResource @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryResource @cascade { organization { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryResource @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryResource @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
     delete:
        { rule: "{$type: {eq: \"internal-account/v1\"}}" },  
    )
{
    id: String! @id 
    resourceId: String  @search(by: [exact, regexp])
    name: String  @search(by: [exact, regexp])
    organization: Organization! @hasInverse(field: resources)
    cloudAccountName: String! @search(by: [exact])
    cloudProvider: String!  @search(by: [exact])
    resourceType: String  @search(by: [exact, regexp])
    childResources: [AbstractResource!] @hasInverse(field: parentResource)
    parentResource: AbstractResource @hasInverse(field: childResources)
    associatedResources: [AbstractResource!] @hasInverse(field: associatedResources)
    details: String
    enrichedFindings: [EnrichedFinding!] @hasInverse(field: affectedResource)
    applicationDeployments: [ApplicationDeployment!] @hasInverse(field: utilizedResources)
}

type EnrichedFinding  {  
    id: String! @id        
    affectedResource: AbstractResource @hasInverse(field: enrichedFindings)        
    finding:  PolicyEvaluationData @hasInverse(field: enrichedAffectedResources)                            
    affectedAttributes: String  @search(by: [exact, regexp])
    timestamp: DateTime! @search
    affected: Boolean! @search
    scanData: CSPMScan
}

enum ScanStatus{
    runnning
    aborted
    completed
}

type CSPMScan implements Scan {
    id: String! @id
    status: String @search(by:[exact])
    detailedStatus: String
    category: String @search(by: [exact,regexp])
    tag: String @search(by: [exact,regexp])
    createdAt: DateTime @search
    updatedAt: DateTime @search
    associatedResourceScanGroup: [CSPMResourceScanGroup!] @hasInverse(field: cspmScan)
}


type Project
@auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProject @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryProject @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}"},
        ]
    },
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProject @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryProject @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
        ]
    },
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProject @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryProject @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
        ]
    },
    delete: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProject @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryProject @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
        ]
    })
 {
    id: ID!
    name: String! @search(by:[exact,regexp])
    platform: String @search(by:[exact,regexp])
    organization: Organization! @hasInverse(field: projects)
    team: Team @hasInverse(field: projects)
    scanlevel: String @search(by: [exact,regexp])
    createdAt: DateTime! @search
    updatedAt: DateTime! @search
    projectConfigs: [ProjectConfig!] @hasInverse(field: project)
    integratorConfigs: IntegratorConfigs @hasInverse(field: project)
    scans: [ScanTarget!] @hasInverse(field: projects)
}

type ProjectConfig
@auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    },
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    },
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    },
    delete: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryProjectConfig @cascade { project { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    })
{
    id: ID!
    organization: String @search(by:[exact,regexp]) 
    repository: String @search(by:[exact,regexp])
    branch: [String!] @search(by:[exact,regexp])
    branchPattern: String @search(by: [exact,regexp])
    scheduleTime: Int @search
    scheduledScan: Boolean! @search
    createdAt: DateTime! @search
    updatedAt: DateTime! @search
    project: Project! @hasInverse(field: projectConfigs)
}

type ScanTarget
@auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    },
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    },
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    },
    delete: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryScanTarget @cascade { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}"},
        ]
    })
{
    id: ID!
    projects: [Project!] @hasInverse(field: scans)
    organization: String @search(by:[exact,regexp])
    repository: String @search(by:[exact,regexp])
    branch: String @search(by:[exact,regexp])
    lastTriggeredBy: String! @search(by:[exact,regexp])
    lastScannedTime: DateTime! @search
    lastAttemptedTime: DateTime! @search
    createdAt: DateTime! @search
    updatedAt: DateTime! @search
    scanResults: [ScanResult!] @hasInverse(field: scanTarget)
}

type ScanResult
@auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
        ]
    },
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
        ]
    },
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
        ]
    },
    delete: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
{ rule: "query($groups: [String!]) { queryScanResult @cascade { scanTarget { projects { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,write,read]}}) { __typename }}}}}}"},
        ]
    })
{
    id: ID!
    group: String! @search(by:[exact,regexp])
    headCommit: String @search(by:[exact])
    triggerdBy: String! @search(by:[exact,regexp])
    triggerType: String! @search(by:[exact,regexp])
    scanType: String! @search(by:[exact])
    resultFile: String! @search(by:[exact])
    scanTool: String! @search(by:[exact,regexp])
    scannedAt: DateTime! @search
    scanDuration: DateTime! @search
    scanTarget: ScanTarget! @hasInverse(field: scanResults)
}

# Dgraph.Allow-Origin "http://localhost:4200"
# Dgraph.Authorization {"VerificationKey":"","Header":"X-OpsMx-Auth","jwkurl":"http://token-machine:8050/jwk","Namespace":"ssd.opsmx.io","Algo":"","Audience":["ssd.opsmx.io"],"ClosedByDefault":false} `
