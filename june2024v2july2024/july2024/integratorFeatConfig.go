package july2024

const SchemaYaml = `
integrationData:
  - stage: Source
    integrations:
      - integratorType: gitlab
        category: sourcetool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
      - integratorType: github
        category: sourcetool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
      - integratorType: bitbucket
        category: sourcetool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
          username:
            encrypt: false
          password:
            encrypt: true
          workspaceId:
            encrypt: false
          projectKey:
            encrypt: false
          repository:
            encrypt: false
        featureConfigs:
          bitbucketAuthMode:
            default: bearer
          accessLevel:
            default: Workspace
      - integratorType: sonarqube
        category: scanningtool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
        featureConfigs:
          sonarqubeFileInsertion:
            default: inactive
      - integratorType: openssf
        category: scanningtool
        featureConfigs:
          openssfcompliancescan:
            default: active
      - integratorType: virustotal
        category: sourcetool
        integratorConfigs:
          token:
            encrypt: true
      - integratorType: snyk
        category: sourcetool
        integratorConfigs:
          snykOrgId:
            encrypt: false
          token:
            encrypt: true
          url:
            encrypt: false
        featureConfigs:
          sastsnykscan:
            default: Local Mode
      - integratorType: semgrep
        category: sourcetool
        integratorConfigs:
          token:
            encrypt: true
        featureConfigs:
          sastsemgrepscan:
            default: Local Mode
      - integratorType: codacy
        category: sourcetool
        integratorConfigs:
          token:
            encrypt: true
        featureConfigs:
          sastcodacyscan:
            default: Local Mode
  - stage: Build
    integrations:
      - integratorType: jenkins
        category: citool
        integratorConfigs:
          url:
            encrypt: false
          approved_user:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
  - stage: Artifact
    integrations:
      - integratorType: trivy
        category: scanningtool
        featureConfigs:
          vulnerabilityscan:
            default: active
          helmscan:
            default: active
          secretscanforsource:
            default: active
          secretscanforcontainers:
            default: active
          licensescanforsource:
            default: active
          licensescanforcontainers:
            default: active
      - integratorType: docker
        category: dockerregistry
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
      - integratorType: ecr
        category: dockerregistry
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          region:
            encrypt: false
          awsAccessKey:
            encrypt: true
          awsSecretKey:
            encrypt: true
      - integratorType: quay
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
      - integratorType: jfrog
        category: dockerregistry
        integratorConfigs:
          url:
            encrypt: false
          repo:
            encrypt: false
          username:
            encrypt: false
          password:
            encrypt: true
      - integratorType: google-artifact-registry
        category: aptregistry
        integratorConfigs:
          key:
            encrypt: true
          source:
            encrypt: false
      - integratorType: grype
        category: scanningtool
        featureConfigs:
          vulnerabilityscan:
            default: inactive
  - stage: Others
    integrations:
      - integratorType: chatgpt
        category: communications
        integratorConfigs:
          token:
            encrypt: true
      - integratorType: slack
        category: communications
        integratorConfigs:
          channel:
            encrypt: false
          token:
            encrypt: true
      - integratorType: jira
        category: communications
        integratorConfigs:
          projectKey:
            encrypt: false
          username:
            encrypt: false
          url:
            encrypt: false
          token:
            encrypt: true
      - integratorType: custompolicy
        category: managementtool
        integratorConfigs:
          url:
            encrypt: false
          token:
            encrypt: true
`
