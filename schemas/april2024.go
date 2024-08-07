package schemas

const April2024Schema = `type SchemaVersion {
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
    name: String!
    value: String!
}


type Organization implements RBAC
    @withSubscription
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryOrganization @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryOrganization @cascade { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryOrganization @cascade { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}}"},
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
    featureModes: [FeatureMode!] @hasInverse(field: organization)
}

"""
Environment can be things like dev, prod, staging etc.
"""
type Environment {
    id: String! @id
    organization: Organization!
    purpose: String! @search(by: [exact])
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
{ rule: "query($groups: [String!]) { queryDeploymentTarget @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
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
    name: String! @search(by: [exact])
    ip: String! @search(by: [exact])
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
{ rule: "query($groups: [String!]) { queryTeam @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryTeam @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryTeam @cascade { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
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
    roles: [Role!]
    organization: Organization! @hasInverse(field: teams)
    applications: [Application!]
    labels: [KeyValue!]
    policies: [PolicyDefinition!] @hasInverse(field: ownerTeam)
    policyEnforcements: [PolicyEnforcement!]
}

type Application implements RBAC
    @withSubscription
    @auth(
    query: {
        or: [
           { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryApplication @cascade { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryApplication @cascade { team { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}}"},
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
    name: String! @search(by: [exact])
    roles: [Role!]
    environments: [ApplicationEnvironment!] @hasInverse(field: application)
    team: Team! @hasInverse(field: applications)
    policies: [PolicyDefinition!] @hasInverse(field: ownerApplication)
    policyEnforcements: [PolicyEnforcement!] @hasInverse(field: enforcedApplication)
    metadata: [KeyValue!]
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
    namespace: String! @search(by:[exact])
    "toolsUsed is a comma-separated string that contains all the tools(source, build, artifact, deploy etc) for an app env"
    toolsUsed: String
    deployments: [ApplicationDeployment!] @hasInverse(field: applicationEnvironment)
    riskStatus: ApplicationRiskStatus @hasInverse(field: applicationEnvironment)
    metadata: [KeyValue!]
}

"""
RiskStatus tells us what risk a current application instance or a deployment is at.
"""
enum RiskStatus {
    lowrisk
    mediumrisk
    highrisk
    apocalypserisk
    inprogress
}

"""
ApplicationRiskStatus tells us about the risk status and alerts for different stages for an application environment.
"""
type ApplicationRiskStatus {
    id: ID!
    riskStatus: RiskStatus @search
    sourceCodeAlerts: Int
    buildAlerts: Int
    artifactAlerts: Int
    deploymentAlerts: Int
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
    "artifact that is deployed"
    artifact: [Artifact!] 
    applicationEnvironment: ApplicationEnvironment!
    deployedAt: DateTime @search
    "deploymentStage is an enum and can be discovered, current, previous or blocked"
    deploymentStage: DeploymentStage! @search(by: [exact])
    "source is argo, spinnaker etc"
    source: String!
    "component would be a service"
    component: String! @search(by: [exact])
    "user who deployed the artifact"
    deployedBy: String
    "toolsUsed contains tools of different stages of source, build, artifact and deploy along with some different tools"
    toolsUsed: ToolsUsed!
    "deploymentRisk is the risk status of the deployment"
    deploymentRisk: ApplicationDeploymentRisk @hasInverse(field: applicationDeployment)
    "policyRunHistory is the policy execution history for this deployment"
    policyRunHistory: [RunHistory!] @hasInverse(field: applicationDeployment)
}

type ToolsUsed {
    id: ID!
    source: String
    build: String
    artifact: String
    deploy: String
    sbom: String
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
    deploymentRiskStatus: RiskStatus
    applicationDeployment: ApplicationDeployment! @hasInverse(field: deploymentRisk)
}


type Integrator
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryIntegrator @cascade { organization { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}}}"},
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
    name: String! @search(by: [exact])     
    type: String! @search(by: [exact])   
    category: String! @search(by: [exact])
    credentials: Credentials!
    createdAt: DateTime!
    updatedAt: DateTime! 
}

type Credentials {
    id: ID! 
    data: String!
    integrator: Integrator! @hasInverse(field: credentials)  
}


type FeatureMode
    @auth(
    query: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryFeatureMode @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}"},
{ rule: "query($groups: [String!]) { queryFeatureMode @cascade { organization { teams { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}}"},
{ rule: "query($groups: [String!]) { queryFeatureMode @cascade { organization { teams { applications { roles(filter: {group: {in: $groups}, permission: {in: [admin,read]}}) { __typename }}}}}}"},
    ]},
    add: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryFeatureMode @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    update: {
        or: [
            { rule: "{$type: {eq: \"internal-account/v1\"}}" },
{ rule: "query($groups: [String!]) { queryFeatureMode @cascade { organization { roles(filter: {group: {in: $groups}, permission: {in: [admin]}}) { __typename }}}}"},
    ]},
    delete: 
        { rule: "{$type: {eq: \"internal-account/v1\"}}" }
            )
{
    id: String! @id
    organization: Organization!   
    scan: String! @search(by: [exact]) 
    type: String! @search(by: [exact])
    enabled: Boolean!
    category: String! @search(by: [exact])
    createdAt: DateTime!
    updatedAt: DateTime! 
}



"""
Tag tells us about the tags that are linked to policies and other components.
"""
type Tag {
    id: String! @id @search(by:[exact])
	tagName: String! @search(by:[exact])
	tagValue: String! @search(by:[exact])
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
    policyName: String! @search(by: [exact])
    category: String! @search(by: [exact])
    stage: String! @search(by: [exact])
    description: String!
    scheduledPolicy: Boolean!
    script: String! 
    variables: String  
    conditionName: String 
    suggestion: String 
}

type PolicyEnforcement {
    id: ID!
    policy: PolicyDefinition!
    #It should be either of the three or else if node is shared it will make changes to 2 different destination, how to enforce that?
    enforcedOrg: Organization @hasInverse(field: policyEnforcements)
    enforcedTeam: Team @hasInverse(field: policyEnforcements)
    enforcedApplication: Application @hasInverse(field: policyEnforcements)
    status: Boolean! @search
    forceApply: Boolean 
    severity: Severity!
    datasourceTool: String! @search(by: [exact])
    action: String! @search(by: [exact])
    conditionValue: String
    environments: [Environment!]
    tags: [Tag!] @hasInverse(field: policies)
    createdAt: DateTime!
    updatedAt: DateTime!
}

type RunHistory  {
    id: ID!
    policyId: String! @search(by: [exact])          
    applicationDeployment: ApplicationDeployment! @hasInverse(field: policyRunHistory)
    PolicyName: String! @search(by: [exact])  
    Severity: Severity! @search(by: [exact])              
    Stage: String! @search(by: [exact])             
    Artifact: String! @search(by: [exact])        
    ArtifactTag: String! @search(by: [exact])       
    ArtifactSha: String! @search(by: [exact])             
    ArtifactNameTag: String! @search(by: [exact])              
    Status: String!
    DatasourceTool: String!          
    AlertTitle: String @search(by: [exact])         
    AlertMessage: String @search(by: [exact])       
    Suggestions: String @search(by: [exact]) 
    Reason: String   
    CreatedAt: DateTime! @search
    UpdatedAt: DateTime! @search
    DeployedAt: DateTime! @search
    Action: String! @search(by: [exact])              
    Hash: String                  
    Error: String @search(by: [exact])                 
    Pass: Boolean! @search 
    MetaData: String  
    FileApi: String
    JiraUrl: String 
    scheduledPolicy: Boolean! @search
    policyEnforcements: PolicyEnforcement! 
}


"""
BuildTool contains data from build tool events.
"""
type BuildTool {
    "id is randomly assigned"
    id: String! @id
    "buildId is a unique job id, run id for a job/pipeline/action"
    buildId: String! @search(by: [exact])
    "tool is jenkins etc"
    tool: String! @search(by: [exact])
    "buildName is the name of the job/pipeline/action"
    buildName: String! @search(by: [exact])
    buildUrl: String! @search(by: [exact])
    artifactType: String  @search(by: [exact])
    "artifact would be something like nginx without the tag"
    artifact: String! @search(by: [exact])
    "artifactTag would be the tag of the artifact"
    artifactTag: String! @search(by: [exact])
    "digest is the sha of the artifact"
    digest: String! @search(by: [exact])
    "buildDigest is the sha of the artifact as sent from the build tool"
    buildDigest: String @search(by: [exact]) 
    "artifactNode links a BuildTool node to an artifact"
    artifactNode: Artifact
    "buildTime is the time at which the artifact was built"
    buildTime: DateTime
    "buildUser is the user that built the artifact"
    buildUser: String
    "sourceCodeTool links a BuildTool node to the source details"
    sourceCodeTool: SourceCodeTool @hasInverse(field: buildTool)
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
    repository: String!
    "branch is the git branch on which the artifact was built"
    branch: String!
    "headCommit is the checkout out head commit"
    headCommit: String
    "diffCommits is a comma separated string of the commits between the previous built artifact and the current"
    diffCommits: String
    licenseName: String
    visibility: String
    "parentRepo is populated in case the git repo is a fork"
    parentRepo: String
    buildTool: BuildTool! 
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
    artifactName: String! @search(by: [exact])
    artifactTag: String! @search(by: [exact])
    artifactSha: String! @search(by: [exact])
    scanData: [ArtifactScanData!] 
}

type ArtifactScanData {
    id: String! @id
    artifactSha: String! @search(by: [exact])
    tool: String! @search(by: [exact])
    artifactDetails: Artifact @hasInverse(field: scanData)
    lastScannedAt: DateTime
    components: [Component!]
    vulnCriticalCount: Int @search
    vulnHighCount: Int @search
    vulnMediumCount: Int @search
    vulnLowCount: Int @search
    vulnInfoCount: Int @search
    vulnUnknownCount: Int @search
    vulnNoneCount: Int @search
    vulnTotalCount: Int @search
}

type Component {
    id: String! @id
    type: String!
    name: String! @search(by: [exact])
    version: String! @search(by: [exact])
    licenses: [String!]
    purl: String @search(by: [exact])
    cpe: String @search(by: [exact])
    scannedAt: DateTime
    vulnerabilities: [Vulnerability!] @hasInverse(field: affects)
    artifacts: [ArtifactScanData!] @hasInverse(field: components)
}

enum Severity {
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
    parent: String! @search(by: [exact])
    ratings: Severity @search(by: [exact])
    cwes: [CWE!]
    summary: String
    detail: String
    recommendation: String
    published: DateTime
    modified: DateTime
    createdAt: DateTime @search
    cvss: [CVSS!]
    affects: [Component!] @hasInverse(field: vulnerabilities)
}

type CWE {
    id: String! @id
    name: String!
    description: String
}

type CVSS {
    type: String
    score: String
}

# Dgraph.Allow-Origin "http://localhost:4200"
# Dgraph.Authorization {"VerificationKey":"","Header":"X-OpsMx-Auth","jwkurl":"http://token-machine:8050/jwk","Namespace":"ssd.opsmx.io","Algo":"","Audience":["ssd.opsmx.io"],"ClosedByDefault":false}`
