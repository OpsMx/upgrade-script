package july2024august2024

import (
	"context"
	"fmt"
	"upgradationScript/july2024august2024/august2024"
	"upgradationScript/july2024august2024/july2024"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func performJiraDetailsTransition(prodDgraphClient, expDgraphClient graphql.Client) error {

	ctx := context.Background()

	prodArtifactScanDataFiles, err := july2024.GetAttachedJiraUrl(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performJiraDetailsTransition: could'nt query old prod jira url from run history to initiate transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Commencing scanned files transition iterations to complete %d -----------------", len(prodArtifactScanDataFiles.QueryArtifactScanData))

	for iter, eachArtifactScanData := range prodArtifactScanDataFiles.QueryArtifactScanData {
		logger.Logger.Debug("---------------------------------------------")
		logger.Sl.Debugf("Scanned files Iteration %d to begin", iter)

		scannedFilesList := make([]*july2024.ScanFileResultRef, 0, 12)

		if eachArtifactScanData.SbomUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sbom",
				Url:  eachArtifactScanData.SbomUrl,
			})
		}

		if eachArtifactScanData.ArtifactLicenseScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "artifactLicenseScan",
				Url:  eachArtifactScanData.ArtifactLicenseScanUrl,
			})
		}

		if eachArtifactScanData.ArtifactSecretScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "artifactSecretScan",
				Url:  eachArtifactScanData.ArtifactSecretScanUrl,
			})
		}

		if eachArtifactScanData.SourceLicenseScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceLicenseScan",
				Url:  eachArtifactScanData.SourceLicenseScanUrl,
			})
		}

		if eachArtifactScanData.SourceSecretScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceSecretScan",
				Url:  eachArtifactScanData.SourceSecretScanUrl,
			})
		}

		if eachArtifactScanData.SourceScorecardScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceScorecardScan",
				Url:  eachArtifactScanData.SourceScorecardScanUrl,
			})
		}

		if eachArtifactScanData.SourceSemgrepHighSeverityScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceSemgrepHighSeverityScan",
				Url:  eachArtifactScanData.SourceSemgrepHighSeverityScanUrl,
			})
		}

		if eachArtifactScanData.SourceSemgrepMediumSeverityScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceSemgrepMediumSeverityScan",
				Url:  eachArtifactScanData.SourceSemgrepMediumSeverityScanUrl,
			})
		}

		if eachArtifactScanData.SourceSemgrepLowSeverityScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceSemgrepLowSeverityScan",
				Url:  eachArtifactScanData.SourceSemgrepLowSeverityScanUrl,
			})
		}

		if eachArtifactScanData.SourceSnykScanUrl != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "sourceSnykScan",
				Url:  eachArtifactScanData.SourceSnykScanUrl,
			})
		}

		if eachArtifactScanData.VirusTotalUrlScan != "" {

			scannedFilesList = append(scannedFilesList, &july2024.ScanFileResultRef{
				Name: "virusTotalScan",
				Url:  eachArtifactScanData.VirusTotalUrlScan,
			})
		}

		logger.Sl.Debug("updating scan files of artifact scan data id: %s", eachArtifactScanData.Id)

		if _, err := august2024.AttachJiraToRunHistory(ctx, expDgraphClient, scannedFilesList, eachArtifactScanData.Id); err != nil {
			return fmt.Errorf("performScanFilesTransition: UpdateScannedFilesInArtifactScanData error: %s", err.Error())
		}
		logger.Sl.Debug("updated scanned files successfully")

		logger.Sl.Debugf("scan files Iteration %d completed", iter)
		logger.Logger.Debug("---------------------------------------------")
	}

	logger.Logger.Info("------------Artifact-Scanned Files upgrade complete-------------------------")

	return nil
}
