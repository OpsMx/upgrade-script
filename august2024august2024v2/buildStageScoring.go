package august2024august2024v2

import (
	"github.com/Khan/genqlient/graphql"
)

func calculateScoring(prodDgraphClient graphql.Client) error {

	// ctx := context.Background()

	// prodArtifactScanDataFiles, err := july2024.GetAttachedJiraUrl(ctx, prodDgraphClient)
	// if err != nil {
	// 	return fmt.Errorf("error: could'nt query old prod jira url from run history to initiate transition: %s", err.Error())
	// }

	// if prodArtifactScanDataFiles == nil {
	// 	logger.Logger.Info("No record for runhistory found in db while excetuing performJiraDetailsTransition")
	// 	return nil
	// }

	// if len(prodArtifactScanDataFiles.QueryRunHistory) == 0 {
	// 	logger.Logger.Info("No record for runhistory found in db while excetuing performJiraDetailsTransition")
	// 	return nil
	// }

	// logger.Sl.Debugf("--------------Number of jira urls for transition iterations are %d -----------------", len(prodArtifactScanDataFiles.QueryRunHistory))

	// orgName := prodArtifactScanDataFiles.QueryRunHistory[0].PolicyEnforcements.EnforcedOrg.Name
	// secretData, err := getCredentials(orgName, "jira", prodDgraphClient)
	// if err != nil {
	// 	return fmt.Errorf("error: getCredentials: orgName: %s type: %s %s", orgName, "jira", err.Error())
	// }

	// var translatedJiraDetails []*august2024.AddJiraInput
	// for iter, eachRunHistory := range prodArtifactScanDataFiles.QueryRunHistory {
	// 	logger.Logger.Debug("---------------------------------------------")
	// 	logger.Sl.Debugf("Jira Transaltion Iteration %d to begin", iter)

	// 	jiraTicketUrl := eachRunHistory.JiraUrl

	// 	splittedArr := strings.Split(jiraTicketUrl, "/")
	// 	extractedTicketKey := splittedArr[len(splittedArr)-1]

	// 	ticketDetails, err := getJiraTicketDetails(extractedTicketKey, secretData.Jira.Url, secretData.Jira.Username, secretData.Jira.Token)
	// 	if err != nil {
	// 		return fmt.Errorf("error: getJiraTicketDetails: %s", err.Error())
	// 	}

	// 	currTime := time.Now()
	// 	entryDetails := august2024.AddJiraInput{
	// 		JiraId:    ticketDetails.Id,
	// 		Url:       jiraTicketUrl,
	// 		Status:    ticketDetails.Fields.Status.Name,
	// 		CreatedAt: &currTime,
	// 		UpdatedAt: &currTime,
	// 		AffectsIndividualComponent: &august2024.RunHistoryRef{
	// 			Id: eachRunHistory.Id,
	// 		},
	// 	}
	// 	translatedJiraDetails = append(translatedJiraDetails, &entryDetails)

	// 	logger.Sl.Debugf("jira translation Iteration %d completed", iter)

	// }

	// logger.Sl.Debug("updating jira translated values into new jira sturct")

	// if _, err := august2024.AttachJiraToRunHistory(ctx, expDgraphClient, translatedJiraDetails); err != nil {
	// 	return fmt.Errorf("error: AttachJiraToRunHistory: %s", err.Error())
	// }
	// logger.Sl.Debug("updating jira translated values into new jira sturct")

	// logger.Logger.Debug("---------------------------------------------")

	// logger.Logger.Info("------------Jira New Struct UPGRADE COMPLETE-------------------------")

	return nil
}
