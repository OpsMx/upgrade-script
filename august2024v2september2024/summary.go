package august2024v2september2024

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func setSummaryNodeForSecurityIssue(gqlClient graphql.Client) error {
	logger.Sl.Debugf("-----setting SummaryNode For SecurityIssues--------")

	countOfSecurityIssues, err := AggregateSecurityIssue(context.Background(), gqlClient)
	if err != nil {
		return fmt.Errorf("AggregateSecurityIssue: error: %s", err.Error())
	}

	totalRecords := *countOfSecurityIssues.AggregateSecurityIssue.Count
	maxThreads := 300

	// Calculate how many threads we should spawn
	numThreads := maxThreads
	if totalRecords < maxThreads {
		numThreads = totalRecords
	}

	// Calculate the chunk size for each thread
	chunkSize := totalRecords / numThreads
	remainder := totalRecords % numThreads

	var wg sync.WaitGroup
	errorChannel := make(chan error, 1)

	batch := 1

	for i := 0; i < numThreads; i++ {
		start := i * chunkSize
		end := start + chunkSize - 1

		// Distribute remainder records by adding 1 to the first 'remainder' threads
		if i < remainder {
			end++
		}

		wg.Add(1)

		// Launch the goroutine
		go func(start, end int) {

			defer wg.Done()

			offset := start
			last := end

			summaries := []*AddSecurityIssueAffectsSummaryInput{}

			for count := start; count <= end; count++ {

				securityissueResp, err := QuerySecurityIssue(context.Background(), gqlClient, &batch, &offset)
				if err != nil {
					errorChannel <- fmt.Errorf("QuerySecurityIssue: %s", err.Error())
					return
				}

				artifactScanIdsInDeployment := []string{}
				mapIds := make(map[string]*AddSecurityIssueAffectsSummaryInput)

				for _, securityIssue := range securityissueResp.QuerySecurityIssue {
					logger.Sl.Debugf("Security Issue id ", *securityIssue.Id)

					for _, deploymentDetails := range securityIssue.DeploymentAnalysisNotHavingExceptions {

						serviceName := deploymentDetails.ApplicationDeployment.Component
						appEnvId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Id
						appId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Application.Id
						teamId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Application.Team.Id
						orgId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Application.Team.Organization.Id

						artifactScanIdResp, err := QueryArtifactScanData(context.Background(), gqlClient, deploymentDetails.ArtifactSha, deploymentDetails.ApplicationDeployment.ToolsUsed.Sbom)
						if err != nil {
							errorChannel <- fmt.Errorf("QueryArtifactScanData: artifactSha:%s tool:%s error:%s", deploymentDetails.ArtifactSha, deploymentDetails.ApplicationDeployment.ToolsUsed.Sbom, err.Error())
							return
						}

						artifactScanId := artifactScanIdResp.QueryArtifactScanData[0].Id

						// if same scan Id in diff deployment data
						artifactScanIdsInDeployment = appendIfNotPresent(artifactScanIdsInDeployment, artifactScanId)

						mapId := strings.Join([]string{serviceName, appEnvId, appId, teamId, orgId}, "-")
						element, ok := mapIds[mapId]
						if !ok {

							var CurrentDeployed *ApplicationDeploymentRef
							if deploymentDetails.ApplicationDeployment.DeploymentStage == DeploymentStageCurrent {
								CurrentDeployed = &ApplicationDeploymentRef{
									Id:              deploymentDetails.ApplicationDeployment.Id,
									DeploymentStage: DeploymentStageCurrent,
								}
							}

							mapIds[mapId] = &AddSecurityIssueAffectsSummaryInput{
								Type: "deployment analysis",
								SecurityIssue: &SecurityIssueRef{
									Id:       securityIssue.Id,
									Severity: securityIssue.Severity,
								},
								Service: serviceName,
								ApplicationEnvironment: &ApplicationEnvironmentRef{
									Id: appEnvId,
								},
								Application: &ApplicationRef{
									Id: appId,
								},
								Team: &TeamRef{
									Id: teamId,
								},
								CurrentDeployed: CurrentDeployed,
								ArtifactScanTS: []*ArtifactScanDataTSRef{
									{
										Artifact: &ArtifactScanDataRef{
											Id: artifactScanId,
										},
										Timestamps: []*time.Time{deploymentDetails.ApplicationDeployment.DeployedAt},
									},
								},
							}

							continue
						}

						alreadyPresent := false
						for i, artifactScanIdPresent := range element.ArtifactScanTS {
							if artifactScanId == artifactScanIdPresent.Artifact.Id {

								artifactDeployedAtFound := false
								alreadyPresent = true

								for _, eachTs := range artifactScanIdPresent.Timestamps {
									timeValue := *eachTs
									if timeValue.Equal(*deploymentDetails.ApplicationDeployment.DeployedAt) {
										artifactDeployedAtFound = true
									}
								}

								if !artifactDeployedAtFound {
									currentData := element.ArtifactScanTS[i]
									currentData.Timestamps = append(currentData.Timestamps, deploymentDetails.ApplicationDeployment.DeployedAt)
									element.ArtifactScanTS[i] = currentData
								}

							}
						}

						if alreadyPresent {

							if deploymentDetails.ApplicationDeployment.DeploymentStage == DeploymentStageCurrent {
								element.CurrentDeployed = &ApplicationDeploymentRef{
									Id:              deploymentDetails.ApplicationDeployment.Id,
									DeploymentStage: DeploymentStageCurrent,
								}
								mapIds[mapId] = element
							}

							continue
						}

						element.ArtifactScanTS = append(element.ArtifactScanTS, &ArtifactScanDataTSRef{
							Artifact: &ArtifactScanDataRef{
								Id: artifactScanId,
							},
							Timestamps: []*time.Time{deploymentDetails.ApplicationDeployment.DeployedAt},
						})

						if deploymentDetails.ApplicationDeployment.DeploymentStage == DeploymentStageCurrent {
							element.CurrentDeployed = &ApplicationDeploymentRef{
								Id:              deploymentDetails.ApplicationDeployment.Id,
								DeploymentStage: DeploymentStageCurrent,
							}
						}

						mapIds[mapId] = element

					}

					for _, deploymentDetails := range securityIssue.DeploymentAnalysisHavingExceptions {

						serviceName := deploymentDetails.ApplicationDeployment.Component
						appEnvId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Id
						appId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Application.Id
						teamId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Application.Team.Id
						orgId := deploymentDetails.ApplicationDeployment.ApplicationEnvironment.Application.Team.Organization.Id
						exceptionId := deploymentDetails.Exception.Id

						artifactScanIdResp, err := QueryArtifactScanData(context.Background(), gqlClient, deploymentDetails.ArtifactSha, deploymentDetails.ApplicationDeployment.ToolsUsed.Sbom)
						if err != nil {
							errorChannel <- fmt.Errorf("QueryArtifactScanData: artifactSha:%s tool:%s error:%s", deploymentDetails.ArtifactSha, deploymentDetails.ApplicationDeployment.ToolsUsed.Sbom, err.Error())
							return

						}

						artifactScanId := artifactScanIdResp.QueryArtifactScanData[0].Id

						// if same scan Id in diff deployment data
						artifactScanIdsInDeployment = appendIfNotPresent(artifactScanIdsInDeployment, artifactScanId)

						mapId := strings.Join([]string{*exceptionId, serviceName, appEnvId, appId, teamId, orgId}, "-")
						element, ok := mapIds[mapId]
						if !ok {

							var CurrentDeployed *ApplicationDeploymentRef
							if deploymentDetails.ApplicationDeployment.DeploymentStage == DeploymentStageCurrent {
								CurrentDeployed = &ApplicationDeploymentRef{
									Id:              deploymentDetails.ApplicationDeployment.Id,
									DeploymentStage: DeploymentStageCurrent,
								}
							}

							mapIds[mapId] = &AddSecurityIssueAffectsSummaryInput{
								Type: "deployment analysis",
								SecurityIssue: &SecurityIssueRef{
									Id:       securityIssue.Id,
									Severity: securityIssue.Severity,
								},
								Service: serviceName,
								ApplicationEnvironment: &ApplicationEnvironmentRef{
									Id: appEnvId,
								},
								Application: &ApplicationRef{
									Id: appId,
								},
								Team: &TeamRef{
									Id: teamId,
								},
								ArtifactScanTS: []*ArtifactScanDataTSRef{
									{
										Artifact: &ArtifactScanDataRef{
											Id: artifactScanId,
										},
										Timestamps: []*time.Time{deploymentDetails.ApplicationDeployment.DeployedAt},
									},
								},
								Exception: &ExceptionAffectsRef{
									Id: exceptionId,
								},
								CurrentDeployed: CurrentDeployed,
							}
							continue
						}

						alreadyPresent := false
						for i, artifactScanIdPresent := range element.ArtifactScanTS {
							if artifactScanId == artifactScanIdPresent.Artifact.Id {

								artifactDeployedAtFound := false
								alreadyPresent = true

								for _, eachTs := range artifactScanIdPresent.Timestamps {
									timeValue := *eachTs
									if timeValue.Equal(*deploymentDetails.ApplicationDeployment.DeployedAt) {
										artifactDeployedAtFound = true
									}
								}

								if !artifactDeployedAtFound {
									currentData := element.ArtifactScanTS[i]
									currentData.Timestamps = append(currentData.Timestamps, deploymentDetails.ApplicationDeployment.DeployedAt)
									element.ArtifactScanTS[i] = currentData
								}

							}
						}

						if alreadyPresent {
							if deploymentDetails.ApplicationDeployment.DeploymentStage == DeploymentStageCurrent {
								element.CurrentDeployed = &ApplicationDeploymentRef{
									Id:              deploymentDetails.ApplicationDeployment.Id,
									DeploymentStage: DeploymentStageCurrent,
								}
								mapIds[mapId] = element
							}
							continue
						}

						element.ArtifactScanTS = append(element.ArtifactScanTS, &ArtifactScanDataTSRef{
							Artifact: &ArtifactScanDataRef{
								Id: artifactScanId,
							},
							Timestamps: []*time.Time{deploymentDetails.ApplicationDeployment.DeployedAt},
						})

						if deploymentDetails.ApplicationDeployment.DeploymentStage == DeploymentStageCurrent {
							element.CurrentDeployed = &ApplicationDeploymentRef{
								Id:              deploymentDetails.ApplicationDeployment.Id,
								DeploymentStage: DeploymentStageCurrent,
							}
						}

						mapIds[mapId] = element

					}

					summaryForPreDeploymentWOException := &AddSecurityIssueAffectsSummaryInput{
						Type: "pre-deployment analysis",
						SecurityIssue: &SecurityIssueRef{
							Id:       securityIssue.Id,
							Severity: securityIssue.Severity,
						},
					}

					for _, artifactAnalysisDetails := range securityIssue.PredeploymentAnalysisNotHavingException {
						artifactScanId := artifactAnalysisDetails.ArtifactScan.Id

						if checkIfPresent(artifactScanIdsInDeployment, artifactScanId) {
							continue
						}

						summaryForPreDeploymentWOException.ArtifactScanTS = append(summaryForPreDeploymentWOException.ArtifactScanTS, &ArtifactScanDataTSRef{
							Artifact: &ArtifactScanDataRef{
								Id: artifactScanId,
							},
							Timestamps: []*time.Time{artifactAnalysisDetails.ArtifactScan.CreatedAt},
						})
					}

					mapIds["allArtifactsWOException"] = summaryForPreDeploymentWOException

					for _, artifactAnalysisDetails := range securityIssue.PredeploymentAnalysisHavingException {

						artifactScanId := artifactAnalysisDetails.ArtifactScan.Id
						exceptionId := artifactAnalysisDetails.Exception.Id

						if checkIfPresent(artifactScanIdsInDeployment, artifactScanId) {
							continue
						}

						mapId := strings.Join([]string{*exceptionId, artifactScanId}, "-")
						element, ok := mapIds[mapId]
						if !ok {
							mapIds[mapId] = &AddSecurityIssueAffectsSummaryInput{
								Type: "pre-deployment analysis",
								SecurityIssue: &SecurityIssueRef{
									Id:       securityIssue.Id,
									Severity: securityIssue.Severity,
								},

								ArtifactScanTS: []*ArtifactScanDataTSRef{
									{
										Artifact: &ArtifactScanDataRef{
											Id: artifactScanId,
										},
										Timestamps: []*time.Time{artifactAnalysisDetails.ArtifactScan.CreatedAt},
									},
								},
								Exception: &ExceptionAffectsRef{
									Id: exceptionId,
								},
							}
							continue
						}

						alreadyPresent := false
						for _, artifactScanIdPresent := range element.ArtifactScanTS {
							if artifactScanId == artifactScanIdPresent.Artifact.Id {
								alreadyPresent = true
							}
						}

						if alreadyPresent {
							continue
						}

						element.ArtifactScanTS = append(element.ArtifactScanTS, &ArtifactScanDataTSRef{
							Artifact: &ArtifactScanDataRef{
								Id: artifactScanId,
							},
							Timestamps: []*time.Time{artifactAnalysisDetails.ArtifactScan.CreatedAt},
						})

						mapIds[mapId] = element

					}
				}

				for _, summary := range mapIds {
					summaries = append(summaries, summary)
				}

				offset += batch

				if offset > last {
					break
				}

			}

			d, err := json.MarshalIndent(summaries, "", " ")
			if err != nil {
				errorChannel <- fmt.Errorf("error json marshal for start:%v end:%v error: %s", start, end, err.Error())
			}
			err = saveToFile(fmt.Sprintf("summaries-%d-%d.json", start, end), d)
			if err != nil {
				errorChannel <- fmt.Errorf("error saving to file for start:%v end:%v error: %s", start, end, err.Error())
			}

		}(start, end)
	}

	// Wait for all goroutines to complete

	go func() {
		wg.Wait()
		close(errorChannel)
	}()

	for err := range errorChannel {

		if err == nil {
			goto startIngestingSummary
		}
		return err

	}

startIngestingSummary:
	// At this point, all summaries have been collected
	dir := "./"

	// Get a list of all files in the directory
	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("error reading directory: %s", err.Error())
	}

	for _, file := range files {
		// Check if the file name starts with "summaries-"
		if strings.HasPrefix(file.Name(), "summaries-") {
			// Read the content of the file
			fileContent, err := os.ReadFile(dir + file.Name())
			if err != nil {
				return fmt.Errorf("failed to read file %s: %v", dir+file.Name(), err.Error())
			}

			summaries := []*AddSecurityIssueAffectsSummaryInput{}
			if err := json.Unmarshal(fileContent, &summaries); err != nil {
				return fmt.Errorf("json Unmarshal %s: %v", dir+file.Name(), err.Error())
			}

			logger.Sl.Debugf("ADDING SUMMARIES OF ", file.Name())
			if _, err := AddSecurityIssueAffectsSummary(context.Background(), gqlClient, summaries); err != nil {
				return fmt.Errorf("AddSecurityIssueAffectsSummary: err:%s", err.Error())
			}
		}
	}

	logger.Sl.Debugf("-----populated SummaryNode For SecurityIssues--------")
	return nil
}

func checkIfPresent(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true // String already present, return original slice
		}
	}
	return false
}

func appendIfNotPresent(slice []string, str string) []string {

	if str == "" || str == "[]" {
		return slice
	}

	for _, s := range slice {
		if s == str {
			return slice // String already present, return original slice
		}
	}
	return append(slice, str) // String not present, append it to the slice
}

func saveToFile(filename string, data []byte) error {
	// Create the file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write data to the file
	_, err = file.Write(data)
	return err
}
