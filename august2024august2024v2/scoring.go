package august2024august2024v2

import (
	"context"
	"fmt"
	"math"
	"strings"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func calculateScoring(prodDgraphClient graphql.Client) error {

	ctx := context.Background()

	_, err := DeleteArtifactScanDataForInprogress(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error in DeleteArtifactScanDataForInprogress: %s", err.Error())
	}

	_, err = DeleteArtifactScanDataNotHaveArtifact(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error in DeleteArtifactScanDataNotHaveArtifact: %s", err.Error())
	}

	prodArtifactScanDataIds, err := GetArtifactScanDataId(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: could'nt query prod artifact scan data id: %s", err.Error())
	}

	if prodArtifactScanDataIds == nil || len(prodArtifactScanDataIds.QueryArtifactScanData) == 0 {
		logger.Logger.Info("No record of artifact scan data found in db to perform artifactRiskScore calculation")
		return nil
	}

	logger.Sl.Debugf("----------Number of artifact scan data to perform artifactRiskScore calculation are %d -----------", len(prodArtifactScanDataIds.QueryArtifactScanData))

	for iter, eachArtifactScanData := range prodArtifactScanDataIds.QueryArtifactScanData {

		logger.Sl.Debug("----------------------------------------------")
		logger.Sl.Debugf("calculating score for artifact scan data id: %s current iteration: %d", eachArtifactScanData.Id, iter)

		logger.Sl.Debug("creating artifact risk id")
		updateResp, err := UpdateArtifactScanData(ctx, prodDgraphClient, eachArtifactScanData.Id)
		if err != nil {
			return fmt.Errorf("error: UpdateArtifactScanData: artifact scan data id: %s err: %s", eachArtifactScanData.Id, err.Error())
		}

		eachArtifactScanData.ArtifactRisk = (*GetArtifactScanDataIdQueryArtifactScanDataArtifactRisk)(updateResp.UpdateArtifactScanData.ArtifactScanData[0].ArtifactRisk)

		logger.Sl.Debug("created artifact risk id", eachArtifactScanData.ArtifactRisk.Id)

		scoring := Scoring{
			Policy: make(map[string][]PolicyDetail),
		}

		uniquePolicyIdMap := make(map[string]bool)

		artifactRunHistories, err := QueryArtifactScanDataRunHistory(context.Background(), prodDgraphClient, eachArtifactScanData.Id)
		if err != nil {
			return fmt.Errorf("error: QueryArtifactScanDataRunHistory: artifact scan data id: %s err: %s", eachArtifactScanData.Id, err.Error())
		}

		if len(artifactRunHistories.QueryArtifactScanData) == 0 {
			logger.Sl.Debugf("Deleting iteration of scandata id: %s as runhistory record not found", eachArtifactScanData.Id)
			if _, err := DeleteArtifactScanData(context.Background(), prodDgraphClient, eachArtifactScanData.Id); err != nil {
				return fmt.Errorf("error: DeleteArtifactScanData: artifact scan data id: %s err: %s", eachArtifactScanData.Id, err.Error())
			}
			continue
		}

		logger.Sl.Debugf("---Total run histories found for this scan_data: %d---", len(artifactRunHistories.QueryArtifactScanData[0].ArtifactRunHistory))

		for _, val := range artifactRunHistories.QueryArtifactScanData[0].ArtifactRunHistory {

			if uniquePolicyIdMap[val.PolicyId] {
				continue
			}

			if val.Status == RunHistoryStatusException {
				continue
			}

			stage := strings.ToLower(val.Stage)

			severity := val.PolicyEnforcements.Severity
			if val.SecurityIssue != nil {
				severity = val.SecurityIssue.Severity
			}

			policyDetail := PolicyDetail{
				PolicyName: val.PolicyName,
				Stage:      stage,
				Severity:   string(severity),
				Status:     Fail,
			}

			if val.Pass != nil && *val.Pass {
				policyDetail.Status = Pass
			}

			scoring.Policy[stage] = append(scoring.Policy[stage], policyDetail)
			uniquePolicyIdMap[val.PolicyId] = true
		}

		if scoring.Policy == nil {
			logger.Sl.Debug("No Policy To Calculate Score")
			continue
		}

		stageCount := 0
		totalScore := 0
		updateImageRisk := true
		// step1: loop and find  score for stages available
		for stage, policiesDetail := range scoring.Policy {

			logger.Sl.Debugf("computation level at policy and stage: %s", stage)

			policyStatusCount := PolicyStatusCount{}

			// step 1a : calculating severity based policy counts
			for _, policyDetail := range policiesDetail {
				policyStatusCount = ProcessPolicyData(policyDetail, policyStatusCount)
			}

			if policyStatusCount.CriticalCount != policyStatusCount.CriticalPassCount {
				stageScore := 0
				riskStatus := RiskStatusApocalypserisk
				updateImageRisk = false

				if err := setArtifactRisk(ctx, prodDgraphClient, stage, *eachArtifactScanData.ArtifactRisk.Id, stageScore, &riskStatus); err != nil {
					return fmt.Errorf("setArtifactRisk: scanDataId: %s riskStatus: %s err: %s", eachArtifactScanData.Id, RiskStatusApocalypserisk, err.Error())
				}

				logger.Sl.Debugf("critical policy failed for stage: %s setting riskStatus as Apocalypserisk", stage)
				continue
			}

			stageScore := calculateStageScore(policyStatusCount)
			logger.Sl.Debugf("calculated stage: %s score: %d", stage, stageScore)

			if err := setArtifactRisk(ctx, prodDgraphClient, stage, *eachArtifactScanData.ArtifactRisk.Id, stageScore, nil); err != nil {
				return fmt.Errorf("setArtifactRisk: scanDataId: %s while setting stage score err: %s", eachArtifactScanData.Id, err.Error())
			}

		}

		if !updateImageRisk {
			logger.Sl.Debug("artifactRisk is already set to Apocalypserisk skipping for calculation of total score")
			continue
		}

		artifactRisk, err := getArtifactRiskScoreDetails(ctx, prodDgraphClient, *eachArtifactScanData.ArtifactRisk.Id)
		if err != nil {
			return fmt.Errorf("%s", err.Error())

		}

		if artifactRisk == nil {
			return fmt.Errorf("artifactRisk status details are not present while executing getArtifactRiskScoreDetails scan data id %s", eachArtifactScanData.Id)
		}

		if artifactRisk.BuildAlertsScore != nil {
			stageCount++
			totalScore += *artifactRisk.BuildAlertsScore
		}

		if artifactRisk.SourceCodeAlertsScore != nil {
			stageCount++
			totalScore += *artifactRisk.SourceCodeAlertsScore
		}

		if artifactRisk.ArtifactAlertsScore != nil {
			stageCount++
			totalScore += *artifactRisk.ArtifactAlertsScore
		}

		if artifactRisk.DeploymentAlertsScore != nil {
			stageCount++
			totalScore += *artifactRisk.DeploymentAlertsScore
		}

		if updateImageRisk && stageCount != 0 {
			logger.Sl.Debugf("total_score: %d and stageCount: %d for iteration: %d", totalScore, stageCount, iter)

			finalScore := totalScore / stageCount

			imageRiskStatus := CalculateImageStatus(finalScore)

			logger.Sl.Debugf("image_risk_status dervied from score: %s", imageRiskStatus)

			if err := setArtifactRisk(ctx, prodDgraphClient, ImageRisk, *eachArtifactScanData.ArtifactRisk.Id, 0, &imageRiskStatus); err != nil {
				return fmt.Errorf("setArtifactRisk: scanDataId: %s while setting stage score err: %s", eachArtifactScanData.Id, err.Error())

			}

		}
		logger.Sl.Debugf("score calculation Iteration %d completed", iter)
	}

	logger.Logger.Debug("---------------------------------------------")

	logger.Logger.Info("------------Scoring Calculation COMPLETE-------------------------")

	return nil
}

func ProcessPolicyData(policyDetail PolicyDetail, policyStatusCount PolicyStatusCount) PolicyStatusCount {

	if strings.ToLower(policyDetail.Severity) == Low {
		policyStatusCount.LowCount++
	}
	if strings.ToLower(policyDetail.Severity) == Medium {
		policyStatusCount.MediumCount++
	}
	if strings.ToLower(policyDetail.Severity) == Critical {
		policyStatusCount.CriticalCount++
	}
	if strings.ToLower(policyDetail.Severity) == High {
		policyStatusCount.HighCount++
	}

	if strings.ToLower(policyDetail.Status) != Pass {
		return policyStatusCount
	}

	if strings.ToLower(policyDetail.Severity) == Low {
		policyStatusCount.LowPassCount++
	}
	if strings.ToLower(policyDetail.Severity) == Medium {
		policyStatusCount.MediumPassCount++
	}
	if strings.ToLower(policyDetail.Severity) == Critical {
		policyStatusCount.CriticalPassCount++
	}
	if strings.ToLower(policyDetail.Severity) == High {
		policyStatusCount.HighPassCount++
	}

	return policyStatusCount
}

func calculateStageScore(policyStatusCount PolicyStatusCount) int {

	lowScore := 0
	mediumScore := 0
	highScore := 0
	criticalScore := 0
	scoreCarryOn := 0

	if policyStatusCount.LowCount > 0 {
		lowScore = policyStatusCount.LowCount + scoreCarryOn
		scoreCarryOn = lowScore
	}

	if policyStatusCount.MediumCount > 0 {
		mediumScore = int(math.Ceil(float64(policyStatusCount.MediumCount)*1.25)) + scoreCarryOn
		scoreCarryOn = mediumScore
	}

	if policyStatusCount.HighCount > 0 {
		highScore = int(math.Ceil(float64(policyStatusCount.HighCount)*1.5)) + scoreCarryOn
		scoreCarryOn = highScore
	}

	if policyStatusCount.CriticalCount > 0 {
		criticalScore = (policyStatusCount.CriticalCount * 2) + scoreCarryOn
	}

	totalScore := lowScore + mediumScore + highScore + criticalScore

	passScore := 0.0
	if policyStatusCount.LowPassCount > 0 {
		perPolicyScore := float64(lowScore) / float64(policyStatusCount.LowCount)
		passScore += math.Ceil(perPolicyScore * float64(policyStatusCount.LowPassCount))
	}

	if policyStatusCount.MediumPassCount > 0 {
		perPolicyScore := float64(mediumScore) / float64(policyStatusCount.MediumCount)
		passScore += math.Ceil(perPolicyScore * float64(policyStatusCount.MediumPassCount))
	}

	if policyStatusCount.HighPassCount > 0 {
		perPolicyScore := float64(highScore) / float64(policyStatusCount.HighCount)
		passScore += math.Ceil(perPolicyScore * float64(policyStatusCount.HighPassCount))

	}

	if policyStatusCount.CriticalPassCount > 0 {
		perPolicyScore := float64(criticalScore) / float64(policyStatusCount.CriticalCount)
		passScore += math.Ceil(perPolicyScore * float64(policyStatusCount.CriticalPassCount))
	}

	finalScore := int((passScore / float64(totalScore)) * 100)
	return finalScore
}

func setArtifactRisk(ctx context.Context, prodDgraphClient graphql.Client, stage, riskId string, score int, riskStatus *RiskStatus) error {

	artifactRisk, err := getArtifactRiskScoreDetails(ctx, prodDgraphClient, riskId)
	if err != nil {
		return fmt.Errorf("%s", err.Error())
	}

	if riskStatus == nil {
		scanning := RiskStatusScanning
		riskStatus = &scanning
		if string(artifactRisk.ArtifactRiskStatus) != "" {
			riskStatus = &artifactRisk.ArtifactRiskStatus
		}
	}

	logger.Sl.Debugf("updating these values in db stage: %s score: %d risk_status: %s", stage, score, &riskStatus)

	switch stage {
	case SOURCE:
		return updateArtifactScoreStatus(ctx, prodDgraphClient, riskId, &score, artifactRisk.BuildAlertsScore, artifactRisk.ArtifactAlertsScore, artifactRisk.DeploymentAlertsScore, *riskStatus)
	case BUILD:
		return updateArtifactScoreStatus(ctx, prodDgraphClient, riskId, artifactRisk.SourceCodeAlertsScore, &score, artifactRisk.ArtifactAlertsScore, artifactRisk.DeploymentAlertsScore, *riskStatus)
	case ARTIFACT:
		return updateArtifactScoreStatus(ctx, prodDgraphClient, riskId, artifactRisk.SourceCodeAlertsScore, artifactRisk.BuildAlertsScore, &score, artifactRisk.DeploymentAlertsScore, *riskStatus)
	case DEPLOY:
		return updateArtifactScoreStatus(ctx, prodDgraphClient, riskId, artifactRisk.SourceCodeAlertsScore, artifactRisk.BuildAlertsScore, artifactRisk.ArtifactAlertsScore, &score, *riskStatus)
	case ImageRisk:
		return updateArtifactScoreStatus(ctx, prodDgraphClient, riskId, artifactRisk.SourceCodeAlertsScore, artifactRisk.BuildAlertsScore, artifactRisk.ArtifactAlertsScore, artifactRisk.DeploymentAlertsScore, *riskStatus)
	}

	return nil
}

func getArtifactRiskScoreDetails(ctx context.Context, prodDgraphClient graphql.Client, artifactRiskId string) (*GetArtifactRiskGetArtifactRisk, error) {

	data, err := GetArtifactRisk(ctx, prodDgraphClient, &artifactRiskId)
	if err != nil {
		return nil, fmt.Errorf("error: GetArtifactRisk: artifactRiskId: %s: %s", artifactRiskId, err.Error())
	}

	return data.GetArtifactRisk, nil
}

func updateArtifactScoreStatus(ctx context.Context, prodDgraphClient graphql.Client, riskId string, sourceCodeAlertsScore *int, buildAlertsScore *int, artifactAlertsScore *int, deploymentAlertsScore *int, imageRiskStatus RiskStatus) error {

	_, err := UpdateArtifactScanDataRiskScoreAndStatus(ctx, prodDgraphClient, &riskId, imageRiskStatus, sourceCodeAlertsScore, buildAlertsScore, artifactAlertsScore, deploymentAlertsScore)
	if err != nil {
		return fmt.Errorf("error: UpdateArtifactScanDataRiskScoreAndStatus: RiskId: %s buildAlertsScore: %v sourceCodeAlertsScore: %v artifactAlertsScore: %v deploymentAlertsScore: %v imageRiskStatus: %v : %s", riskId, convIntPointerToString(buildAlertsScore), convIntPointerToString(sourceCodeAlertsScore), convIntPointerToString(artifactAlertsScore), convIntPointerToString(deploymentAlertsScore), imageRiskStatus, err.Error())
	}

	return nil

}
