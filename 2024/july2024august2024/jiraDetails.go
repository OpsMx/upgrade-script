package july2024august2024

import (
	"context"
	"fmt"
	"strings"
	"time"
	"upgradationScript/2024/july2024august2024/august2024"
	"upgradationScript/2024/july2024august2024/july2024"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func performJiraDetailsTransition(prodDgraphClient, expDgraphClient graphql.Client) error {

	ctx := context.Background()

	prodArtifactScanDataFiles, err := july2024.GetAttachedJiraUrl(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: could'nt query old prod jira url from run history to initiate transition: %s", err.Error())
	}

	if prodArtifactScanDataFiles == nil || len(prodArtifactScanDataFiles.QueryRunHistory) == 0 {
		logger.Logger.Info("No record for runhistory found in db while excetuing performJiraDetailsTransition")
		return nil
	}

	filteredRunHistory := filterEmptyJiraUrls(prodArtifactScanDataFiles.QueryRunHistory)

	if len(filteredRunHistory) == 0 {
		logger.Logger.Info("No non-empty record for jiraurl found in db while excetuing performJiraDetailsTransition")
		return nil
	}

	logger.Sl.Debugf("--------------Number of jira urls for transition iterations are %d -----------------", len(filteredRunHistory))

	secretData, err := getCredentials("jira", prodDgraphClient)
	if err != nil {
		return fmt.Errorf("error: getCredentials: type: %s %s", "jira", err.Error())
	}

	var translatedJiraDetails []*august2024.AddJiraInput
	for iter, eachRunHistory := range filteredRunHistory {
		logger.Logger.Debug("---------------------------------------------")
		logger.Sl.Debugf("Jira Translation Iteration %d to begin", iter)

		jiraTicketUrl := eachRunHistory.JiraUrl

		splittedArr := strings.Split(jiraTicketUrl, "/")
		extractedTicketKey := splittedArr[len(splittedArr)-1]

		ticketDetails, err := getJiraTicketDetails(extractedTicketKey, secretData.Jira.Url, secretData.Jira.Username, secretData.Jira.Token)
		if err != nil {
			return fmt.Errorf("error: getJiraTicketDetails: %s", err.Error())
		}

		layout := "2006-01-02T15:04:05.000-0700"
		createdAt, err := time.Parse(layout, ticketDetails.Fields.Created)
		if err != nil {
			return fmt.Errorf("error: time.Parse: for created at %s", err.Error())
		}

		updatedAt, err := time.Parse(layout, ticketDetails.Fields.Updated)
		if err != nil {
			return fmt.Errorf("error: time.Parse: for updated at %s", err.Error())
		}

		entryDetails := august2024.AddJiraInput{
			JiraId:    ticketDetails.Id,
			Url:       jiraTicketUrl,
			Status:    ticketDetails.Fields.Status.Name,
			CreatedAt: &createdAt,
			UpdatedAt: &updatedAt,
			AffectsIndividualComponent: &august2024.RunHistoryRef{
				Id: eachRunHistory.Id,
			},
		}
		translatedJiraDetails = append(translatedJiraDetails, &entryDetails)

		logger.Sl.Debugf("jira translation Iteration %d completed", iter)

	}

	logger.Sl.Debug("updating jira translated values into new jira struct")

	if _, err := august2024.AttachJiraToRunHistory(ctx, expDgraphClient, translatedJiraDetails); err != nil {
		return fmt.Errorf("error: AttachJiraToRunHistory: %s", err.Error())
	}
	logger.Sl.Debug("updated jira translated values into new jira struct")

	logger.Logger.Debug("---------------------------------------------")

	logger.Logger.Info("------------Jira New Struct UPGRADE COMPLETE-------------------------")

	return nil
}
