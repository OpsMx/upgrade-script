package policyingenstionscript

var scriptMap = map[int]string{
	1: `
	package opsmx

	import future.keywords.in

	default allow = false
	default private_repo = ""
	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/", request_components)

	token := input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {"Authorization": sprintf("Bearer %v", [token])},
	}

	response = http.send(request)

	private_repo = response.body.private

	allow {
		response.status_code = 200
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration for repository %s/%s.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		not policy_name in exception_list
		private_repo == false
		msg := sprintf("Repository %v/%v is found to be publically accessible.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to security standards by restricting public accessibility of Github repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		policy_name in exception_list
		private_repo == false
		msg := sprintf("Repository %v/%v is found to be publically accessible.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to security standards by restricting public accessibility of Github repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	2: `
	package opsmx
	import future.keywords.in		

	default allow = false
	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	required_min_reviewers = {input.conditions[i].condition_value|input.conditions[i].condition_name == "Minimum Reviewers Policy"}

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch, "protection"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)
	reviewers = response.body.required_pull_request_reviews.required_approving_review_count

	allow {
		response.status_code = 200
	}
	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository branch protection policy configuration for branch %s of repository %s/%s due to Bad Credentials.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The branch protection policy for %s branch for Repository %s/%s not found while trying to fetch repository branch protection policy configuration.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the branch protection policy is configured."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository branch configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		not response.status_code in [401, 404, 500, 200, 301, 302]
		msg := ""
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration for %v/%v.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		reviewers == 0
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that mandates a pull request before merging has been deactivated for the %s branch of the %v/%v repository on GitHub.", [input.metadata.branch,input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s/%s Github repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		reviewers == 0
		policy_name in exception_list
		msg := sprintf("The branch protection policy that mandates a pull request before merging has been deactivated for the %s branch of the %v/%v repository on GitHub.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s/%s Github repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		reviewers < required_min_reviewers
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the %v/%v repository on GitHub.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s/%s Github repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		reviewers < required_min_reviewers
		policy_name in exception_list
		msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the %v/%v repository on GitHub.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s /%s Github repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	3: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code = 404
		response.body.message != "Branch not protected"
		msg := sprintf("Repository, Branch or Branch Protection Policy not found while trying to fetch Repository Configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository and branch provided are correct and the access token has rights to read repository configuration. Also, verify if Branch Protection Policy is enabled."
		error := sprintf("Repository, Branch or Branch Protection Policy not found while trying to fetch Repository Configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration for repository %s/%s.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		policy_name in exception_list
		response.body.message == "Branch not protected"
		msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policies for %v/%v Github repository.",[input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": "active"}]{
		not policy_name in exception_list
		response.body.message == "Branch not protected"
		msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policies for %v/%v Github repository.",[input.metadata.owner, input.metadata.repository])
		error := ""
	}`,

	4: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection"]
	request_url = concat("/", request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The branch protection policy for %s branch for Repository %s/%s not found while trying to fetch repository branch protection policy configuration.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the branch protection policy is configured."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository branch protection policy configuration for branch %s of repository %s/%s due to Bad Credentials.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository branch configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		not response.status_code in [401, 404, 500, 200, 301, 302]
		msg := ""
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration for %v/%v.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.allow_deletions.enabled == true
		policy_name in exception_list
		msg := sprintf("Deletion of Branch is not restricted for Branch %v of Github Repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Restrict Branch Deletion operations by enforcing required branch protection policies on branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.allow_deletions.enabled == true
		not policy_name in exception_list
		msg := sprintf("Deletion of Branch is not restricted for Branch %v of Github Repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Restrict Branch Deletion operations by enforcing required branch protection policies on branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}`,

	5: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection", "required_signatures"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository branch protection policy configuration for branch %s of repository %s/%s due to Bad Credentials.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The branch protection policy for %s branch for Repository %s/%s not found while trying to fetch repository branch protection policy configuration.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the branch protection policy is configured."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository branch configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		not response.status_code in [401, 404, 500, 200, 301, 302]
		msg := ""
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration for %v/%v.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code in [200, 302]
		response.body.enabled != true
		policy_name in exception_list
		msg := sprintf("Branch %v of Github Repository %v/%v does not have signed commits mandatory.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enforcing all commits to be signed for %v/%v Github repository.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "exception"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code in [200, 302]
		response.body.enabled != true
		not policy_name in exception_list
		msg := sprintf("Branch %v of Github Repository %v/%v does not have signed commits mandatory.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enforcing all commits to be signed for %v/%v Github repository.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "active"
	}`,

	6: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "orgs", input.metadata.owner]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	mfa_enabled = response.body.two_factor_requirement_enabled



	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := "Unauthorized to check organisation configuration due to Bad Credentials."
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get organisation configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := "Mentioned Organisation not found while trying to fetch organisation configuration. The repository does not belong to an organisation."
		sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration. Also, verify if the repository belongs to an organisation. The two-factor authentication feature is not provided for individual repositories which are not owned by any oranisation."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking organisation configuration for %s.", [input.metadata.owner])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		mfa_enabled == null
		policy_name in exception_list
		msg := sprintf("Github Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enabling 2FA for %s organisation.",[input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		mfa_enabled == null
		not policy_name in exception_list
		msg := sprintf("Github Organisation %v does not have the mfa enabled.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enabling 2FA for %s organisation.",[input.metadata.owner])
		error := ""
		alertStatus := "active"
	}`,

	7: `
	package opsmx
	severities = ["LOW"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity
		msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
	}`,

	8: `
	package opsmx
	severities = ["CRITICAL"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity
		msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
	}
	`,

	9: `
	package opsmx
	severities = ["MODERATE","UNDEFINED","MEDIUM","UNKNOWN"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity 
		msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
	} `,

	10: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"orgs", input.metadata.owner, "actions", "permissions", "workflow"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check Organisation Workflow Permissions for organisation %s due to Bad Credentials.", [input.metadata.owner])
		error := sprintf("401 Unauthorized. Unauthorized to check Workflow Permissions for organisation %s due to Bad Credentials.", [input.metadata.owner])
		sugg := "Kindly check the access token. It must have enough permissions to get organisation workflow permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := "Mentioned Organisation not found while trying to fetch organisation workflow permissions."
		sugg := "Kindly check if the organisation provided is correct."
		error := "Organisation name is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking organisation workflow configuration for %s.", [input.metadata.owner])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := "Unable to fetch organisation workflow permissions."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation workflow permissions.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions != "read"
		policy_name in exception_list
		msg := sprintf("Default workflow permissions for Organisation %v is not set to read.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Organisation %s to read only.", [input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions != "read"
		not policy_name in exception_list
		msg := sprintf("Default workflow permissions for Organisation %v is not set to read.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Organisation %s to read only.", [input.metadata.owner])
		error := ""
		alertStatus := "active"
	}`,

	11: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "actions", "permissions", "workflow"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check Repository Workflow Permissions for organisation %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check Workflow Permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get organisation workflow permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := "Mentioned Repository or workflows not found while trying to fetch repository workflow permissions."
		sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration. Also, verify if the repository belongs to an organisation. The two-factor authentication feature is not provided for individual repositories which are not owned by any oranisation."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository workflow configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository workflow permissions."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository workflow permissions.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions != "read"
		not policy_name in exception_list
		msg := sprintf("Default workflow permissions for Repository %v/%v is not set to read.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Repository %v/%v to read only.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions != "read"
		policy_name in exception_list
		msg := sprintf("Default workflow permissions for Repository %v/%v is not set to read.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Repository %v/%v to read only.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	12: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.build_image_sha == "" 
		msg = ""
		sugg = "Ensure that build platform is integrated with SSD."
		error = "Complete Build Artifact information could not be identified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.image_sha == ""
		msg = ""
		sugg = "Ensure that deployment platform is integrated with SSD using Admission Controller."
		error = "Artifact information could not be identified from Deployment Environment."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		not policy_name in exception_list
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		policy_name in exception_list
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
		alertStatus := "exception"
	}`,

	13: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_scorecard.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_scorecard.json"]) {
		input.metadata.source_code_path != ""
	}

	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")

	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", file_name, "&", "checkName=", check_name, "&", "scanOperation=", "openssfScan"])

	request = {
		"method": "GET",
		"url": request_url,
	}

	response = http.send(request)


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.code == 404
		msg := ""
		sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
		error := sprintf("Error Received: %v.",[response.body.error])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := ""
		sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
		error := sprintf("Error Received: %v.",[response.body.error])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved: %v", [response.body.error])
		sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
		alertStatus := "error"
	}

	default in_range = false

	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}

	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		in_range == true
		response.body.score < threshold
		not policy_name in exception_list
		documentation := response.body.documentationUrl 
		msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
		sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		in_range == true
		response.body.score < threshold
		policy_name in exception_list
		documentation := response.body.documentationUrl 
		msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
		sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
		error := ""
		alertStatus := "exception"
	}`,

	32: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	outside_collaborators_url = concat("/", [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=outside&per_page=100"])

	request = {
		"method": "GET",
		"url": outside_collaborators_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}

	default response = ""
	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository collaborators for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code in [200, 301, 302]
		count(response.body) > 0
		not policy_name in exception_list
		collaborators_list = concat(",\n", [response.body[i].login | response.body[i].type == "User"]) 
		msg := sprintf("%v outside collaborators have access to repository. \n The list of outside collaborators is: %v.", [count(response.body), collaborators_list])
		sugg := "Adhere to the company policy by revoking the access of non-organization members for Github repo."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code in [200, 301, 302]
		count(response.body) > 0
		policy_name in exception_list
		collaborators_list = concat(",\n", [response.body[i].login | response.body[i].type == "User"]) 
		msg := sprintf("%v outside collaborators have access to repository. \n The list of outside collaborators is: %v.", [count(response.body), collaborators_list])
		sugg := "Adhere to the company policy by revoking the access of non-organization members for Github repo."
		error := ""
		alertStatus := "exception"
	}`,

	33: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_url = concat("/", [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=admin"])

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}


	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository collaborators for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := [response.body[i].login | response.body[i].type == "User"]
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Github Repository is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Github Repository is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "active"
	}`,

	34: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_url = concat("/", [input.metadata.ssd_secret.github.url, "orgs", input.metadata.owner, "members?role=admin"])

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}


	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "401 Unauthorized: Unauthorized to check organisation members."
		sugg := "Kindly check the access token. It must have enough permissions to get organisation members."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read organisation members. Also check if the repository belongs to an organization."
		error := "Mentioned branch for Repository not found while trying to fetch organisation members. Either Organisation/Repository name is incorrect or the repository does not belong to an organization."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking organisation members for %s.", [input.metadata.owner])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch organisation members. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := [response.body[i].login | response.body[i].type == "User"]
		user := users[_]
		patterns := ["r", "bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		not policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Github Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Github Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}`,

	35: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false
	default active_hooks = []
	default active_hooks_count = 0
	default hooks_with_secret = []
	default hooks_with_secret_count = 0

	request_url = concat("/",[input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "hooks"])
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	active_hooks = [response.body[i].config | response.body[i].active == true]
	hooks_with_secret = [response.body[i].config.secret | response.body[i].active == true]

	allow {
		response.status_code = 200
	}


	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository webhook configuration for %s:%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository webhook configuration for %s:%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository webhook configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The webhook configuration for Repository %s/%s not found.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhook configuration."
		msg := ""
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository webhook configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository webhook configuration. Error %v:%v receieved from Github upon trying to fetch repository webhook configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	active_hooks_count = count(active_hooks)
	hooks_with_secret_count = count(hooks_with_secret)
	test = active_hooks_count > hooks_with_secret_count

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		active_hooks_count != 0

		active_hooks_count > hooks_with_secret_count
		policy_name in exception_list
		msg := sprintf("Webhook authentication failed: Secret not set for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by configuring the webhook secret for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""  
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		active_hooks_count != 0

		active_hooks_count > hooks_with_secret_count
		not policy_name in exception_list
		msg := sprintf("Webhook authentication failed: Secret not set for webhooks in %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by configuring the webhook secret for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""  
		alertStatus := "active"
	}`,

	36: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false
	default active_hooks = []
	default active_hooks_count = 0
	default insecure_active_hooks = []
	default insecure_active_hooks_count = 0

	request_url = concat("/",[input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "hooks"])
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	active_hooks = [response.body[i].config | response.body[i].active == true]
	insecure_active_hooks = [active_hooks[j].url | active_hooks[j].insecure_ssl == "1"]

	allow {
		response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository webhook configuration for %s:%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository webhook configuration for %s:%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository webhook configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The webhook configuration for Repository %s/%s not found.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhook configuration."
		msg := ""
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository webhook configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository webhook configuration. Error %v:%v receieved from Github upon trying to fetch repository webhook configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	active_hooks_count = count(active_hooks)
	insecure_active_hooks_count = count(insecure_active_hooks)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		active_hooks_count > 0
		insecure_active_hooks_count > 0
		policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""  
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		active_hooks_count > 0
		insecure_active_hooks_count > 0
		not policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""  
		alertStatus := "active"
	}`,

	37: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	approved_server = split(input.metadata.ssd_secret.build_access_config.url, "/")[2]
	build_url = split(input.metadata.build_url, "/")[2]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		approved_server == ""
		msg:=""
		sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs to strengthen artifact validation during the deployment process."
		error:="The essential list of approved build URLs remains unspecified"
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		approved_server != ""
		build_url != approved_server
		not policy_name in exception_list

		msg:=sprintf("The artifact has not been sourced from an approved build server.\nPlease verify the artifacts origin against the following approved build URLs: %v", [approved_server])
		sugg:="Ensure the artifact is sourced from an approved build server."
		error:=""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		approved_server != ""
		build_url != approved_server
		policy_name in exception_list
		
		msg:=sprintf("The artifact has not been sourced from an approved build server.\nPlease verify the artifacts origin against the following approved build URLs: %v", [approved_server])
		sugg:="Ensure the artifact is sourced from an approved build server."
		error:=""
		alertStatus := "exception"
	}`,

	38: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.build_image_sha == "" 
		msg = ""
		sugg = "Ensure that build platform is integrated with SSD."
		error = "Complete Build Artifact information could not be identified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.image_sha == ""
		msg = ""
		sugg = "Ensure that deployment platform is integrated with SSD using Admission Controller."
		error = "Artifact information could not be identified from Deployment Environment."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		not policy_name in exception_list
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		policy_name in exception_list
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
		alertStatus := "exception"
	}`,

	39: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.build_image_sha == "" 
		msg = ""
		sugg = "Ensure that build platform is integrated with SSD."
		error = "Complete Build Artifact information could not be identified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.image_sha == ""
		msg = ""
		sugg = "Ensure that deployment platform is integrated with SSD using Admission Controller."
		error = "Artifact information could not be identified from Deployment Environment."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		not policy_name in exception_list
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		policy_name in exception_list
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
		alertStatus := "exception"
	}`,

	40: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)
	license_url = response.body.license.url

	allow {
		response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository configurations for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configurations."
		error := "Mentioned branch for Repository not found while trying to fetch repository configurations. Repo name or Organisation is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configurations for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		license_url == null
		not policy_name in exception_list
		msg := sprintf("GitHub License not found for the %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by adding a License file for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		license_url == null
		policy_name in exception_list
		msg := sprintf("GitHub License not found for the %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by adding a License file for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	41: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default approved_artifact_repos = []
	default image_source = ""

	image_details = split(input.metadata.image,"/")

	image_source = concat("/",["docker.io", image_details[0]]) {
		count(image_details) <= 2
		not contains(image_details[0], ".")
	}

	image_source = concat("/",[image_details[0], image_details[1]]) {
		count(image_details) == 2
		contains(image_details[0], ".")
	}

	image_source = concat("/",[image_details[0], image_details[1]]) {
		count(image_details) == 3
	}

	approved_artifact_repos = split(input.metadata.ssd_secret.imageCreds.repo, ",")
	decision:= image_source in approved_artifact_repos
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(approved_artifact_repos) == 0
		error := "The essential list of Authorized Artifact Repositories remains unspecified."
		sugg := "Set the AuthorizedArtifactRepos parameter with trusted Artifact Repo to strengthen artifact validation during the deployment process."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		not image_source in approved_artifact_repos
		not policy_name in exception_list
		msg := sprintf("The artifact %v:%v has not been sourced from an authorized artifact repo.\nPlease verify the artifacts origin against the following Authorized Artifact Repositories: %v", [input.metadata.image, input.metadata.image_tag, input.metadata.ssd_secret.imageCreds.repo])
		sugg := "Ensure the artifact is sourced from an authorized artifact repo."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		not image_source in approved_artifact_repos
		policy_name in exception_list
		msg := sprintf("The artifact %v:%v has not been sourced from an authorized artifact repo.\nPlease verify the artifacts origin against the following Authorized Artifact Repositories: %v", [input.metadata.image, input.metadata.image_tag, input.metadata.ssd_secret.imageCreds.repo])
		sugg := "Ensure the artifact is sourced from an authorized artifact repo."
		error := ""
		alertStatus := "exception"
	}`,

	42: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_scorecard.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_scorecard.json"]) {
		input.metadata.source_code_path != ""
	}

	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")

	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", file_name, "&", "checkName=", check_name, "&", "scanOperation=", "openssfScan"])

	request = {
		"method": "GET",
		"url": request_url,
	}

	response = http.send(request)


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.code == 404
		msg := ""
		sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
		error := sprintf("Error Received: %v.",[response.body.error])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := ""
		sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
		error := sprintf("Error Received: %v.",[response.body.error])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved: %v", [response.body.error])
		sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
		alertStatus := "error"
	}

	default in_range = false

	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}

	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		in_range == true
		response.body.score < threshold
		not policy_name in exception_list
		msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
		sugg := "Refer to detailed OpenSSF ScoreCard report and implement required practices to obtain better OpenSSF Score."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		in_range == true
		response.body.score < threshold
		policy_name in exception_list
		msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
		sugg := "Refer to detailed OpenSSF ScoreCard report and implement required practices to obtain better OpenSSF Score."
		error := ""
		alertStatus := "exception"
	}`,

	43: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_reliability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	44: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_reliability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	45: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_reliability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	46: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	missing(obj, field) {
		not obj[field]
	}

	missing(obj, field) {
		obj[field] == ""
	}

	canonify_cpu(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		endswith(orig, "m")
		new := to_number(replace(orig, "m", ""))
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		not endswith(orig, "m")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", orig,-1)
		new := to_number(orig) * 1000
	}

	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000

	# 10 ** 18
	mem_multiple("P") = 1000000000000000000

	# 10 ** 15
	mem_multiple("T") = 1000000000000000

	# 10 ** 12
	mem_multiple("G") = 1000000000000

	# 10 ** 9
	mem_multiple("M") = 1000000000

	# 10 ** 6
	mem_multiple("k") = 1000000

	# 10 ** 3
	mem_multiple("") = 1000

	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741

	# 10 ** 0
	mem_multiple("m") = 1

	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000

	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000

	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000

	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000

	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000

	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000

	get_suffix(mem) = suffix {
		not is_string(mem)
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 0
		suffix := substring(mem, count(mem) - 1, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		suffix := substring(mem, count(mem) - 2, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		not mem_multiple(substring(mem, count(mem) - 2, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 0
		suffix := ""
	}

	canonify_mem(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_mem(orig) = new {
		not is_number(orig)
		suffix := get_suffix(orig)
		raw := replace(orig, suffix, "")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
		new := to_number(raw) * mem_multiple(suffix)
	}

	# Ephemeral containers not checked as it is not possible to set field.

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		policy_name in exception_list
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		not policy_name in exception_list
		alertStatus := "exception"
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		not canonify_cpu(cpu_orig)
		msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		not canonify_mem(mem_orig)
		msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources.limits
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "cpu")
		msg := sprintf("container <%v> has no cpu limit", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "memory")
		msg := sprintf("container <%v> has no memory limit", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		cpu := canonify_cpu(cpu_orig)
		max_cpu_orig := input.parameters.cpu
		max_cpu := canonify_cpu(max_cpu_orig)
		cpu > max_cpu
		msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed of <%v>", [container.name, cpu_orig, max_cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		mem := canonify_mem(mem_orig)
		max_mem_orig := input.parameters.memory
		max_mem := canonify_mem(max_mem_orig)
		mem > max_mem
		msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed of <%v>", [container.name, mem_orig, max_mem_orig])
	}`,

	47: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	missing(obj, field) = true {
		not obj[field]
	}

	missing(obj, field) = true {
		obj[field] == ""
	}

	canonify_cpu(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		endswith(orig, "m")
		new := to_number(replace(orig, "m", ""))
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		not endswith(orig, "m")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", orig, -1)
		new := to_number(orig) * 1000
	}

	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000 { true }

	# 10 ** 18
	mem_multiple("P") = 1000000000000000000 { true }

	# 10 ** 15
	mem_multiple("T") = 1000000000000000 { true }

	# 10 ** 12
	mem_multiple("G") = 1000000000000 { true }

	# 10 ** 9
	mem_multiple("M") = 1000000000 { true }

	# 10 ** 6
	mem_multiple("k") = 1000000 { true }

	# 10 ** 3
	mem_multiple("") = 1000 { true }

	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741
	# 10 ** 0
	mem_multiple("m") = 1 { true }

	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000 { true }

	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000 { true }

	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000 { true }

	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000 { true }

	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000 { true }

	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000 { true }

	get_suffix(mem) = suffix {
		not is_string(mem)
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 0
		suffix := substring(mem, count(mem) - 1, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		suffix := substring(mem, count(mem) - 2, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		not mem_multiple(substring(mem, count(mem) - 2, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 0
		suffix := ""
	}

	canonify_mem(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_mem(orig) = new {
		not is_number(orig)
		suffix := get_suffix(orig)
		raw := replace(orig, suffix, "")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
		new := to_number(raw) * mem_multiple(suffix)
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to set the resource request limits and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to set the resource request limits and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		policy_name in exception_list
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource request limits and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource request limits and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		policy_name in exception_list
		alertStatus := "exception"
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.requests.cpu
		not canonify_cpu(cpu_orig)
		msg := sprintf("container <%v> cpu request <%v> could not be parsed", [container.name, cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.requests.memory
		not canonify_mem(mem_orig)
		msg := sprintf("container <%v> memory request <%v> could not be parsed", [container.name, mem_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources
		msg := sprintf("container <%v> has no resource requests", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources.requests
		msg := sprintf("container <%v> has no resource requests", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.requests, "cpu")
		msg := sprintf("container <%v> has no cpu request", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.requests, "memory")
		msg := sprintf("container <%v> has no memory request", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.requests.cpu
		cpu := canonify_cpu(cpu_orig)
		max_cpu_orig := input.parameters.cpu
		max_cpu := canonify_cpu(max_cpu_orig)
		cpu > max_cpu
		msg := sprintf("container <%v> cpu request <%v> is higher than the maximum allowed of <%v>", [container.name, cpu_orig, max_cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.requests.memory
		mem := canonify_mem(mem_orig)
		max_mem_orig := input.parameters.memory
		max_mem := canonify_mem(max_mem_orig)
		mem > max_mem
		msg := sprintf("container <%v> memory request <%v> is higher than the maximum allowed of <%v>", [container.name, mem_orig, max_mem_orig])
	}`,

	48: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "high"
	default findings_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_", image_sha, "_semgrep.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=semgrepScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=semgrepScan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings_count = response.body.totalFindings
	findings = response.body.findings

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
		not findings[i].rule_name in exception_list
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the high-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
		findings[i].rule_name in exception_list
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the high-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	49: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "medium"
	default findings_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_", image_sha, "_semgrep.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=semgrepScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=semgrepScan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings_count = response.body.totalFindings
	findings = response.body.findings

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		not findings[i].rule_name in exception_list
		title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the medium-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		findings[i].rule_name in exception_list
		title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the medium-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	50: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	missing(obj, field) = true {
		not obj[field]
	}

	missing(obj, field) = true {
		obj[field] == ""
	}

	canonify_cpu(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		endswith(orig, "m")
		new := to_number(replace(orig, "m", ""))
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		not endswith(orig, "m")
		regex.find_n("^[0-9]+$", orig, -1)
		new := to_number(orig) * 1000
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		not endswith(orig, "m")
		regex.find_n("^[0-9]+[.][0-9]+$", orig, -1)
		new := to_number(orig) * 1000
	}

	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000 { true }

	# 10 ** 18
	mem_multiple("P") = 1000000000000000000 { true }

	# 10 ** 15
	mem_multiple("T") = 1000000000000000 { true }

	# 10 ** 12
	mem_multiple("G") = 1000000000000 { true }

	# 10 ** 9
	mem_multiple("M") = 1000000000 { true }

	# 10 ** 6
	mem_multiple("k") = 1000000 { true }

	# 10 ** 3
	mem_multiple("") = 1000 { true }

	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741
	# 10 ** 0
	mem_multiple("m") = 1 { true }

	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000 { true }

	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000 { true }

	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000 { true }

	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000 { true }

	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000 { true }

	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000 { true }

	get_suffix(mem) = suffix {
		not is_string(mem)
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 0
		suffix := substring(mem, count(mem) - 1, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		suffix := substring(mem, count(mem) - 2, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		not mem_multiple(substring(mem, count(mem) - 2, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 0
		suffix := ""
	}

	canonify_mem(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_mem(orig) = new {
		not is_number(orig)
		suffix := get_suffix(orig)
		raw := replace(orig, suffix, "")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
		new := to_number(raw) * mem_multiple(suffix)
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to set the resource limits and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to set the resource limits and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		policy_name in exception_list
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to set the resource limits and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to set the resource limits and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		policy_name in exception_list
		alertStatus := "exception"
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		not canonify_cpu(cpu_orig)
		msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		not canonify_mem(mem_orig)
		msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.requests.cpu
		not canonify_cpu(cpu_orig)
		msg := sprintf("container <%v> cpu request <%v> could not be parsed", [container.name, cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.requests.memory
		not canonify_mem(mem_orig)
		msg := sprintf("container <%v> memory request <%v> could not be parsed", [container.name, mem_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources.limits
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "cpu")
		msg := sprintf("container <%v> has no cpu limit", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "memory")
		msg := sprintf("container <%v> has no memory limit", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources.requests
		msg := sprintf("container <%v> has no resource requests", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.requests, "cpu")
		msg := sprintf("container <%v> has no cpu request", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.requests, "memory")
		msg := sprintf("container <%v> has no memory request", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_limits_orig := container.resources.limits.cpu
		cpu_limits := canonify_cpu(cpu_limits_orig)
		cpu_requests_orig := container.resources.requests.cpu
		cpu_requests := canonify_cpu(cpu_requests_orig)
		cpu_ratio := object.get(input.parameters, "cpuRatio", input.parameters.ratio)
		to_number(cpu_limits) > to_number(cpu_ratio) * to_number(cpu_requests)
		msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed ratio of <%v>", [container.name, cpu_limits_orig, cpu_ratio])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_limits_orig := container.resources.limits.memory
		mem_requests_orig := container.resources.requests.memory
		mem_limits := canonify_mem(mem_limits_orig)
		mem_requests := canonify_mem(mem_requests_orig)
		mem_ratio := input.parameters.ratio
		to_number(mem_limits) > to_number(mem_ratio) * to_number(mem_requests)
		msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed ratio of <%v>", [container.name, mem_limits_orig, mem_ratio])
	}`,

	51: ``,

	52: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "low"
	default findings_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_", image_sha, "_semgrep.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=semgrepScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=semgrepScan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	findings_count = response.body.totalFindings
	findings = response.body.findings

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		not findings[i].rule_name in exception_list
		title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the low-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		findings[i].rule_name in exception_list
		title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the low-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	53: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privilege escalation containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		not policy_name in exception_list
		c := input_containers[_]
		input_allow_privilege_escalation(c)
		msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privilege escalation containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		policy_name in exception_list
		c := input_containers[_]
		input_allow_privilege_escalation(c)
		msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
		alertStatus := "exception"
	}

	input_allow_privilege_escalation(c) {
		not has_field(c, "securityContext")
	}
	input_allow_privilege_escalation(c) {
		not c.securityContext.allowPrivilegeEscalation == false
	}
	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	has_field(object, field) = true {
		object[field]
	}

	is_update(review) {
		review.operation == "UPDATE"
	}`,

	54: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of AppArmor Profiles..", "error": "", "exception": "", "alertStatus": alertStatus}] {
		metadata := input.request.object.metadata
		container := input_containers[_]
		not input_apparmor_allowed(container, metadata)
		not policy_name in exception_list
		msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.request.object.metadata.name, container.name, input.parameters.allowedProfiles])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of AppArmor Profiles..", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		metadata := input.request.object.metadata
		container := input_containers[_]
		not input_apparmor_allowed(container, metadata)
		policy_name in exception_list
		msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.request.object.metadata.name, container.name, input.parameters.allowedProfiles])
		alertStatus := "exception"
	}

	input_apparmor_allowed(container, metadata) {
		get_annotation_for(container, metadata) == input.parameters.allowedProfiles[_]
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	get_annotation_for(container, metadata) = out {
		out = metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
	}
	get_annotation_for(container, metadata) = out {
		not metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
		out = "runtime/default"
	}`,

	55: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		# spec.containers.securityContext.capabilities field is immutable.
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		has_disallowed_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		# spec.containers.securityContext.capabilities field is immutable.
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		has_disallowed_capabilities(container)
		policy_name in exception_list
		msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		missing_drop_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		missing_drop_capabilities(container)
		policy_name in exception_list
		msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		has_disallowed_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		has_disallowed_capabilities(container)
		policy_name in exception_list
		msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		missing_drop_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		missing_drop_capabilities(container)
		policy_name in exception_list
		msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		has_disallowed_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		has_disallowed_capabilities(container)
		policy_name in exception_list
		msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		missing_drop_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		missing_drop_capabilities(container)
		policy_name in exception_list
		msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "exception"
	}


	has_disallowed_capabilities(container) {
		allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}
		not allowed["*"]
		capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}

		count(capabilities - allowed) > 0
	}

	missing_drop_capabilities(container) {
		must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}
		all := {"all"}
		dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}

		count(must_drop - dropped) > 0
		count(all - dropped) > 0
	}

	get_default(obj, param, _) = out {
		out = obj[param]
	}

	get_default(obj, param, _default) = out {
		not obj[param]
		not obj[param] == false
		out = _default
	}

	is_update(review) {
			review.operation == "UPDATE"
	}`,

	56: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of Flex Volumes.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		# spec.volumes field is immutable.
		not is_update(input.request)

		volume := input_flexvolumes[_]
		not input_flexvolumes_allowed(volume)
		not policy_name in exception_list
		msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.request.object.metadata.name, input.parameters.allowedFlexVolumes])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of Flex Volumes.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		# spec.volumes field is immutable.
		not is_update(input.request)

		volume := input_flexvolumes[_]
		not input_flexvolumes_allowed(volume)
		policy_name in exception_list
		msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.request.object.metadata.name, input.parameters.allowedFlexVolumes])
		alertStatus := "exception"
	}

	input_flexvolumes_allowed(volume) {
		input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
	}

	input_flexvolumes[v] {
		v := input.request.object.spec.volumes[_]
		has_field(v, "flexVolume")
	}

	# has_field returns whether an object has a field
	has_field(object, field) = true {
		object[field]
	}

	is_update(review) {
		review.operation == "UPDATE"
	}`,

	57: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Block if forbidden
	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		# spec.securityContext.sysctls field is immutable.
		not is_update(input.request)

		sysctl := input.request.object.spec.securityContext.sysctls[_].name
		forbidden_sysctl(sysctl)
		not policy_name in exception_list
		msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.forbiddenSysctls])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		# spec.securityContext.sysctls field is immutable.
		not is_update(input.request)

		sysctl := input.request.object.spec.securityContext.sysctls[_].name
		forbidden_sysctl(sysctl)
		policy_name in exception_list
		msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.forbiddenSysctls])
		alertStatus := "exception"
	}

	# Block if not explicitly allowed
	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		sysctl := input.request.object.spec.securityContext.sysctls[_].name
		not allowed_sysctl(sysctl)
		not policy_name in exception_list
		msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.allowedSysctls])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		sysctl := input.request.object.spec.securityContext.sysctls[_].name
		not allowed_sysctl(sysctl)
		policy_name in exception_list
		msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.allowedSysctls])
		alertStatus := "exception"
	}

	# * may be used to forbid all sysctls
	forbidden_sysctl(sysctl) {
		input.parameters.forbiddenSysctls[_] == "*"
	}

	forbidden_sysctl(sysctl) {
		input.parameters.forbiddenSysctls[_] == sysctl
	}

	forbidden_sysctl(sysctl) {
		forbidden := input.parameters.forbiddenSysctls[_]
		endswith(forbidden, "*")
		startswith(sysctl, trim_suffix(forbidden, "*"))
	}

	# * may be used to allow all sysctls
	allowed_sysctl(sysctl) {
		input.parameters.allowedSysctls[_] == "*"
	}

	allowed_sysctl(sysctl) {
		input.parameters.allowedSysctls[_] == sysctl
	}

	allowed_sysctl(sysctl) {
		allowed := input.parameters.allowedSysctls[_]
		endswith(allowed, "*")
		startswith(sysctl, trim_suffix(allowed, "*"))
	}

	is_update(request) {
			request.operation == "UPDATE"
	}`,

	58: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of fsGroup in security context.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		# spec.securityContext.fsGroup field is immutable.
		not is_update(input.request)

		spec := input.request.object.spec
		not input_fsGroup_allowed(spec)
		not policy_name in exception_list
		msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.request.object.metadata.name, input.parameters])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of fsGroup in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		# spec.securityContext.fsGroup field is immutable.
		not is_update(input.request)

		spec := input.request.object.spec
		not input_fsGroup_allowed(spec)
		policy_name in exception_list
		msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.request.object.metadata.name, input.parameters])
		alertStatus := "exception"
	}

	input_fsGroup_allowed(_) {
		# RunAsAny - No range is required. Allows any fsGroup ID to be specified.
		input.parameters.rule == "RunAsAny"
	}
	input_fsGroup_allowed(spec) {
		# MustRunAs - Validates pod spec fsgroup against all ranges
		input.parameters.rule == "MustRunAs"
		fg := spec.securityContext.fsGroup
		count(input.parameters.ranges) > 0
		range := input.parameters.ranges[_]
		value_within_range(range, fg)
	}
	input_fsGroup_allowed(spec) {
		# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
		input.parameters.rule == "MayRunAs"
		not has_field(spec, "securityContext")
	}
	input_fsGroup_allowed(spec) {
		# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
		input.parameters.rule == "MayRunAs"
		not spec.securityContext.fsGroup
	}
	input_fsGroup_allowed(spec) {
		# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
		input.parameters.rule == "MayRunAs"
		fg := spec.securityContext.fsGroup
		count(input.parameters.ranges) > 0
		range := input.parameters.ranges[_]
		value_within_range(range, fg)
	}
	value_within_range(range, value) {
		range.min <= value
		range.max >= value
	}
	# has_field returns whether an object has a field
	has_field(object, field) = true {
		object[field]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	59: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of HostPath volumes.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		volume := input_hostpath_volumes[_]
		allowedPaths := get_allowed_paths(input)
		input_hostpath_violation(allowedPaths, volume)
		not policy_name in exception_list
		msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.request.object.metadata.name, allowedPaths])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of HostPath volumes.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		volume := input_hostpath_volumes[_]
		allowedPaths := get_allowed_paths(input)
		input_hostpath_violation(allowedPaths, volume)
		policy_name in exception_list
		msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.request.object.metadata.name, allowedPaths])
		alertStatus := "exception"
	}

	input_hostpath_violation(allowedPaths, _) {
		allowedPaths == []
	}
	input_hostpath_violation(allowedPaths, volume) {
		not input_hostpath_allowed(allowedPaths, volume)
	}

	get_allowed_paths(arg) = out {
		not arg.parameters
		out = []
	}
	get_allowed_paths(arg) = out {
		not arg.parameters.allowedHostPaths
		out = []
	}
	get_allowed_paths(arg) = out {
		out = arg.parameters.allowedHostPaths
	}

	input_hostpath_allowed(allowedPaths, volume) {
		allowedHostPath := allowedPaths[_]
		path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
		not allowedHostPath.readOnly == true
	}

	input_hostpath_allowed(allowedPaths, volume) {
		allowedHostPath := allowedPaths[_]
		path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
		allowedHostPath.readOnly
		not writeable_input_volume_mounts(volume.name)
	}

	writeable_input_volume_mounts(volume_name) {
		container := input_containers[_]
		mount := container.volumeMounts[_]
		mount.name == volume_name
		not mount.readOnly
	}

	# This allows "/foo", "/foo/", "/foo/bar" etc., but
	# disallows "/fool", "/etc/foo" etc.
	path_matches(prefix, path) {
		a := path_array(prefix)
		b := path_array(path)
		prefix_matches(a, b)
	}
	path_array(p) = out {
		p != "/"
		out := split(trim(p, "/"), "/")
	}
	# This handles the special case for "/", since
	# split(trim("/", "/"), "/") == [""]
	path_array("/") = []

	prefix_matches(a, b) {
		count(a) <= count(b)
		not any_not_equal_upto(a, b, count(a))
	}

	any_not_equal_upto(a, b, n) {
		a[i] != b[i]
		i < n
	}

	input_hostpath_volumes[v] {
		v := input.request.object.spec.volumes[_]
		has_field(v, "hostPath")
	}

	# has_field returns whether an object has a field
	has_field(object, field) = true {
		object[field]
	}
	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	60: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the sharing of host namespaces.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.review)

		input_share_hostnamespace(input.request.object)
		not policy_name in exception_list
		msg := sprintf("Sharing the host namespace is not allowed: %v", [input.request.object.metadata.name])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the sharing of host namespaces.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.review)

		input_share_hostnamespace(input.request.object)
		policy_name in exception_list
		msg := sprintf("Sharing the host namespace is not allowed: %v", [input.request.object.metadata.name])
		alertStatus := "exception"
	}

	input_share_hostnamespace(o) {
		o.spec.hostPID
	}
	input_share_hostnamespace(o) {
		o.spec.hostIPC
	}

	is_update(review) {
		review.operation == "UPDATE"
	}`,

	61: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of hostNetwork and hostPort.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		input_share_hostnetwork(input.request.object)
		not policy_name in exception_list
		msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.request.object.metadata.name, input.parameters])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of hostNetwork and hostPort.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		input_share_hostnetwork(input.request.object)
		policy_name in exception_list
		msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.request.object.metadata.name, input.parameters])
		alertStatus := "exception"
	}

	input_share_hostnetwork(o) {
		not input.parameters.hostNetwork
		o.spec.hostNetwork
	}

	input_share_hostnetwork(_) {
		hostPort := input_containers[_].ports[_].hostPort
		hostPort < input.parameters.min
	}

	input_share_hostnetwork(_) {
		hostPort := input_containers[_].ports[_].hostPort
		hostPort > input.parameters.max
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	62: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privileged containers in security context.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		c.securityContext.privileged
		not policy_name in exception_list
		msg := sprintf("Privileged container is not allowed: %v, securityContext: %v", [c.name, c.securityContext])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privileged containers in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		c.securityContext.privileged
		policy_name in exception_list
		msg := sprintf("Privileged container is not allowed: %v, securityContext: %v", [c.name, c.securityContext])
		alertStatus := "exception"
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	63: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted ProcMount types.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		allowedProcMount := get_allowed_proc_mount(input)
		not input_proc_mount_type_allowed(allowedProcMount, c)
		not policy_name in exception_list
		msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted ProcMount types.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		allowedProcMount := get_allowed_proc_mount(input)
		not input_proc_mount_type_allowed(allowedProcMount, c)
		policy_name in exception_list
		msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
		alertStatus := "exception"
	}

	input_proc_mount_type_allowed(allowedProcMount, c) {
		allowedProcMount == "default"
		lower(c.securityContext.procMount) == "default"
	}
	input_proc_mount_type_allowed(allowedProcMount, _) {
		allowedProcMount == "unmasked"
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
		c.securityContext.procMount
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
		c.securityContext.procMount
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
		c.securityContext.procMount
	}

	get_allowed_proc_mount(arg) = out {
		not arg.parameters
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		not arg.parameters.procMount
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		arg.parameters.procMount
		not valid_proc_mount(arg.parameters.procMount)
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		valid_proc_mount(arg.parameters.procMount)
		out = lower(arg.parameters.procMount)
	}

	valid_proc_mount(str) {
		lower(str) == "default"
	}
	valid_proc_mount(str) {
		lower(str) == "unmasked"
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	64: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to use only read-only root filesystem container.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		input_read_only_root_fs(c)
		not policy_name in exception_list
		msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to use only read-only root filesystem container.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		input_read_only_root_fs(c)
		policy_name in exception_list
		msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
		alertStatus := "exception"
	}

	input_read_only_root_fs(c) {
		not has_field(c, "securityContext")
	}
	input_read_only_root_fs(c) {
		not c.securityContext.readOnlyRootFilesystem == true
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	has_field(object, field) = true {
		object[field]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	65: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of disallowed volume types.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		volume_fields := {x | input.request.object.spec.volumes[_][x]; x != "name"}
		field := volume_fields[_]
		not input_volume_type_allowed(field)
		not policy_name in exception_list
		msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.request.object.metadata.name, input.parameters.volumes])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of disallowed volume types.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		volume_fields := {x | input.request.object.spec.volumes[_][x]; x != "name"}
		field := volume_fields[_]
		not input_volume_type_allowed(field)
		policy_name in exception_list
		msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.request.object.metadata.name, input.parameters.volumes])
		alertStatus := "exception"
	}

	# * may be used to allow all volume types
	input_volume_type_allowed(_) {
		input.parameters.volumes[_] == "*"
	}

	input_volume_type_allowed(field) {
		field == input.parameters.volumes[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,

	66: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default quality_gate_status = ""

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	quality_gate_status := response.body.quality.projectStatus.status

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		quality_gate_status == ""
		msg = "Quality Gate Status for Sonarqube Project could not be accessed."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project. Also, verify if the quality gates for project are correctly configured."
		error = "Failed while fetching quality gate status from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		quality_gate_status != ""
		quality_gate_status != "OK"
		not policy_name in exception_list
		msg = sprintf("Quality Gate Status for Sonarqube Project is %v.", [quality_gate_status])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		quality_gate_status != ""
		quality_gate_status != "OK"
		policy_name in exception_list
		msg = sprintf("Quality Gate Status for Sonarqube Project is %v.", [quality_gate_status])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}`,

	67: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_maintainability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	68: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_maintainability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	69: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_maintainability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	70: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_maintainability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	71: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_security_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	72: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_security_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	73: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_security_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	74: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_security_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	75: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default score = ""

	rating_map := {
		"A": "1.0",
		"B": "2.0",
		"C": "3.0",
		"D": "4.0",
		"E": "5.0"
	}

	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	score = [response.body.measures[i].period.value | response.body.measures[i].metric == "new_reliability_rating"][0]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		score == ""
		msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
		error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		score == required_rating_score
		not policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		score == required_rating_score
		policy_name in exception_list
		msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
		sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
		error := ""
		alertStatus := "exception"
	}`,

	76: `
	package opsmx
	severities = ["HIGH"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity
		msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
	}
	`,

	77: `
	package opsmx
	import future.keywords.in


	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg":msg, "suggestion":suggestion, "error":error, "exception": "", "alertStatus": alertStatus}] {
		policy = input.conditions[0].condition_name																																																																	

		input.metadata.results[i].control_title == policy
		control_struct = input.metadata.results[i]
		failed_resources = control_struct.failed_resources
		counter = count(failed_resources)
		counter > 0
		not policy_name in exception_list
		msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",\n",failed_resources)])
		error := ""
		suggestion := input.metadata.suggestion
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestion":suggestion, "error":error, "exception": policy_name, "alertStatus": alertStatus}] {
		policy = input.conditions[0].condition_name																																																																	

		input.metadata.results[i].control_title == policy
		control_struct = input.metadata.results[i]
		failed_resources = control_struct.failed_resources
		counter = count(failed_resources)
		counter > 0
		policy_name in exception_list
		msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",\n",failed_resources)])
		error := ""
		suggestion := input.metadata.suggestion
		alertStatus := "exception"
	}`,

	198: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	policy = input.conditions[0].condition_name
	control_id = split(policy, " -")[0]


	deny[{"alertMsg":msg, "suggestion":suggestion, "error":"", "exception": "", "alertStatus": alertStatus}] {
		input.metadata.results[i].control_id == control_id
		control_struct = input.metadata.results[i]
		failed_resources = control_struct.failed_resources
		counter = count(failed_resources)
		counter > 0
		not policy_name in exception_list
		msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
		suggestion := input.metadata.suggestion
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestion":suggestion, "error":"", "exception": policy_name, "alertStatus": alertStatus}] {
		input.metadata.results[i].control_id == control_id
		control_struct = input.metadata.results[i]
		failed_resources = control_struct.failed_resources
		counter = count(failed_resources)
		counter > 0
		policy_name in exception_list
		msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
		suggestion := input.metadata.suggestion
		alertStatus := "exception"
	}`,

	249: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	condition_value := input.conditions[0].condition_value
	min_threshold_str := split(condition_value, "-")[0]
	max_threshold_str := split(condition_value, "-")[1]
	min_threshold := to_number(min_threshold_str)
	max_threshold := to_number(max_threshold_str)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": "", "alertStatus": alertStatus}] {
		score := input.metadata.compliance_score
		score > min_threshold
		score <= max_threshold
		not policy_name in exception_list
		msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
		sugg := input.metadata.suggestion
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		score := input.metadata.compliance_score
		score > min_threshold
		score <= max_threshold
		policy_name in exception_list
		msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
		sugg := input.metadata.suggestion
		alertStatus := "exception"
	}`,

	253: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	condition_value := input.conditions[0].condition_value
	min_threshold_str := split(condition_value, "-")[0]
	max_threshold_str := split(condition_value, "-")[1]
	min_threshold := to_number(min_threshold_str)
	max_threshold := to_number(max_threshold_str)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": "", "alertStatus": alertStatus}] {
		score := input.metadata.compliance_score
		score > min_threshold
		score <= max_threshold
		not policy_name in exception_list
		msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
		sugg := input.metadata.suggestion
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		score := input.metadata.compliance_score
		score > min_threshold
		score <= max_threshold
		policy_name in exception_list
		msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
		sugg := input.metadata.suggestion
		alertStatus := "exception"
	}`,

	257: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	condition_value := input.conditions[0].condition_value
	min_threshold_str := split(condition_value, "-")[0]
	max_threshold_str := split(condition_value, "-")[1]
	min_threshold := to_number(min_threshold_str)
	max_threshold := to_number(max_threshold_str)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": "", "alertStatus": alertStatus}] {
		score := input.metadata.compliance_score
		score > min_threshold
		score <= max_threshold
		not policy_name in exception_list
		msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
		sugg := sprintf("Implement best practices as mentioned in %v to improve overall compliance score.", [input.metadata.references])
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		score := input.metadata.compliance_score
		score > min_threshold
		score <= max_threshold
		policy_name in exception_list
		msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
		sugg := sprintf("Implement best practices as mentioned in %v to improve overall compliance score.", [input.metadata.references])
		alertStatus := "exception"
	}`,

	261: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false
	default auto_merge_config = ""

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	auto_merge_config = response.body.allow_auto_merge
	status_code = response.status_code

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The branch protection policy for %s branch for Repository %s/%s not found while trying to fetch repository branch protection policy configuration.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the branch protection policy is configured."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository branch protection policy configuration for branch %s of repository %s/%s due to Bad Credentials.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository branch configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		not response.status_code in [401, 404, 500, 200, 301, 302]
		msg := ""
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration for %v/%v.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		status_code in [200, 301, 302]
		auto_merge_config == ""
		not policy_name in exception_list
		msg = sprintf("Auto Merge Config Not Found, indicates Branch Protection Policy is not set for repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error = ""
		sugg = "Kindly configure Branch Protection Policy for source code repository and make sure to restrict auto merge."
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		status_code in [200, 301, 302]
		auto_merge_config == ""
		policy_name in exception_list
		msg = sprintf("Auto Merge Config Not Found, indicates Branch Protection Policy is not set for repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error = ""
		sugg = "Kindly configure Branch Protection Policy for source code repository and make sure to restrict auto merge."
		alertStatus := "exception"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		status_code in [200, 301, 302]
		auto_merge_config == true
		not policy_name in exception_list
		msg = sprintf("Auto Merge is allowed in github repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error = ""
		sugg = sprintf("Kindly modify existing Branch Protection Policies of github repository %v/%v to restrict Auto Merge operations.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		status_code in [200, 301, 302]
		auto_merge_config == true
		policy_name in exception_list
		msg = sprintf("Auto Merge is allowed in github repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error = ""
		sugg = sprintf("Kindly modify existing Branch Protection Policies of github repository %v/%v to restrict Auto Merge operations.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "exception"
	}`,

	262: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	input_stages = input.metadata.stages
	manualJudgment_stages = [input.metadata.stages[i] | input.metadata.stages[i].type == "manualJudgment"]
	counter = count(manualJudgment_stages)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": "", "alertStatus": alertStatus}]{
		count(manualJudgment_stages) < 1
		not policy_name in exception_list
		msg := "No manual judgement stages configured in pipeline."
		sugg := "Kindly follow security best practices by introducing manual judgement stage before deployment to critical environments."
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": policy_name, "alertStatus": alertStatus}]{
		count(manualJudgment_stages) < 1
		policy_name in exception_list
		msg := "No manual judgement stages configured in pipeline."
		sugg := "Kindly follow security best practices by introducing manual judgement stage before deployment to critical environments."
		alertStatus := "exception"
	}`,

	263: `
	package opsmx
	import future.keywords.in 

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	repo_search = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository]
	repo_searchurl = concat("/",repo_search)

	branch_search = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch]
	branch_searchurl = concat("/",branch_search)

	protect_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch,"protection"]
	protect_url = concat("/",protect_components)

	token = input.metadata.ssd_secret.github.token

	repo_search_request = {
		"method": "GET",
		"url": repo_searchurl,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	branch_search_request = {
		"method": "GET",
		"url": branch_searchurl,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	protect_search_request = {
		"method": "GET",
		"url": protect_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(repo_search_request)

	branch_response = http.send(branch_search_request)

	branch_protect = http.send(protect_search_request)

	branch_check = response.body.branch

	AllowAutoMerge = response.body.allow_auto_merge

	delete_branch_on_merge = response.body.delete_branch_on_merge

	branch_protected = branch_response.body.protected

	RequiredReviewers = branch_protect.body.required_pull_request_reviews.required_approving_review_count

	AllowForcePushes = branch_protect.body.allow_force_pushes.enabled

	AllowDeletions = branch_response.body.allow_deletions.enabled

	RequiredSignatures = branch_protect.body.required_signatures.enabled

	EnforceAdmins = branch_protect.body.enforce_admins.enabled

	RequiredStatusCheck = branch_protect.body.required_status_checks.strict


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		AllowAutoMerge == true
		not policy_name in exception_list
		msg := sprintf("The Auto Merge is enabled for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please disable the Auto Merge for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		AllowAutoMerge == true
		policy_name in exception_list
		msg := sprintf("The Auto Merge is enabled for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please disable the Auto Merge for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		delete_branch_on_merge == true
		not policy_name in exception_list
		msg := "The branch protection policy that allows branch deletion is enabled."
		sugg := sprintf("Please disable the branch deletion of branch %s of repository %s/%s.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		delete_branch_on_merge == true
		policy_name in exception_list
		msg := "The branch protection policy that allows branch deletion is enabled."
		sugg := sprintf("Please disable the branch deletion of branch %s of repository %s/%s.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		branch_protected == false
		not policy_name in exception_list
		msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Make sure branch %v of %v/%v repo has some branch protection policies.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		branch_protected == false
		policy_name in exception_list
		msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Make sure branch %v of %v/%v repo has some branch protection policies.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		RequiredReviewers == 0
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that mandates the minimum review for code merge requests has been deactivated for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Activate branch protection: pull request and minimum 1 approval before merging for branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		RequiredReviewers == 0
		policy_name in exception_list
		msg := sprintf("The branch protection policy that mandates the minimum review for code merge requests has been deactivated for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Activate branch protection: pull request and minimum 1 approval before merging for branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		AllowForcePushes == true
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that allows force pushes is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Disable force push for branch %v of repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		AllowForcePushes == true
		policy_name in exception_list
		msg := sprintf("The branch protection policy that allows force pushes is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Disable force push for branch %v of repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		AllowDeletions == true
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that allows branch deletion is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please disable the branch deletion of branch %v of repository %v/%v.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		AllowDeletions == true
		policy_name in exception_list
		msg := sprintf("The branch protection policy that allows branch deletion is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please disable the branch deletion of branch %v of repository %v/%v.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		RequiredSignatures == true
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that requires signature association with commits is disabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please activate the mandatory GitHub signature policy for branch %v of %v/%v repositoty.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		RequiredSignatures == true
		policy_name in exception_list
		msg := sprintf("The branch protection policy that requires signature association with commits is disabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please activate the mandatory GitHub signature policy for branch %v of %v/%v repositoty.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		EnforceAdmins == true
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that enforces status checks for repository administrators is disabled for repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please activate the branch protection policy, dont by pass status checks for repository administrators of branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		EnforceAdmins == true
		policy_name in exception_list
		msg := sprintf("The branch protection policy that enforces status checks for repository administrators is disabled for repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please activate the branch protection policy, dont by pass status checks for repository administrators of branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		RequiredStatusCheck == true
		not policy_name in exception_list
		msg := sprintf("The branch protection policy that requires status check is disabled for the repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please activate the branch protection policy, requiring a need to be up-to-date with the base branch before merging for branch %s of %s/%s repo",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		RequiredStatusCheck == true
		policy_name in exception_list
		msg := sprintf("The branch protection policy that requires status check is disabled for the repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Please activate the branch protection policy, requiring a need to be up-to-date with the base branch before merging for branch %s of %s/%s repo",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	264: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default approved_servers = ""
	default list_approved_user_str = ""

	list_approved_user_str = input.metadata.ssd_secret.build_access_config.approved_user
	list_approved_users = split(list_approved_user_str, ",")
	approved_servers = input.metadata.ssd_secret.build_access_config.url
	build_url = split(input.metadata.build_url, "/")[2]
	build_user = input.metadata.build_user

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus }] {
		approved_servers == ""
		msg:=""
		sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs and users to strengthen artifact validation during the deployment process."
		error:="The essential list of approved build URLs and users remains unspecified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error,  "exception": "", "alertStatus": alertStatus }]{
		approved_servers != ""
		list_approved_user_str == ""
		msg := ""
		sugg := "Please set the list of authorised users in integrations configuration to strengthen artifact validation during the deployment process."
		error := "The essential list of approved build users remains unspecified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus }]{
		approved_servers != ""
		not input.metadata.build_user in list_approved_users
		not policy_name in exception_list
		msg:=sprintf("The artifact build has not been created by an approved user.\nPlease verify the artifacts origin.\nBuild User: %v \nApproved Users: %v", [build_user, list_approved_user_str])
		sugg:="Ensure the artifact is sourced from an approved user."
		error:=""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus }]{
		approved_servers != ""
		not input.metadata.build_user in list_approved_users
		policy_name in exception_list
		msg:=sprintf("The artifact build has not been created by an approved user.\nPlease verify the artifacts origin.\nBuild User: %v \nApproved Users: %v", [build_user, list_approved_user_str])
		sugg:="Ensure the artifact is sourced from an approved user."
		error:=""
		alertStatus := "exception"
	}`,

	265: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		input.metadata.parent_repo != ""
		parent_repo_owner = split(input.metadata.parent_repo, "/")[0]
		parent_repo_owner != input.metadata.owner
		not policy_category in exception_list
		msg := sprintf("The pipeline uses a forked repo from a different organization %s from %s.", [input.metadata.parent_repo, input.metadata.owner])
		sugg := "Refrain from running pipelines originating from forked repos not belonging to the same organization."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		input.metadata.parent_repo != ""
		parent_repo_owner = split(input.metadata.parent_repo, "/")[0]
		parent_repo_owner != input.metadata.owner
		policy_category in exception_list
		msg := sprintf("The pipeline uses a forked repo from a different organization %s from %s.", [input.metadata.parent_repo, input.metadata.owner])
		sugg := "Refrain from running pipelines originating from forked repos not belonging to the same organization."
		error := ""
		alertStatus := "exception"
	}`,

	266: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	maintainers_url = concat("/", [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?permission=maintain&per_page=100"])
	admins_url = concat("/", [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?permission=admin&per_page=100"])

	maintainers_request = {
		"method": "GET",
		"url": maintainers_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}

	default maintainers_response = ""
	maintainers_response = http.send(maintainers_request)
	maintainers = [maintainers_response.body[i].login | maintainers_response.body[i].type == "User"]

	admins_request = {
		"method": "GET",
		"url": admins_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}

	default admins_response = ""
	admins_response = http.send(admins_request)

	admins = [admins_response.body[i].login | admins_response.body[i].type == "User"]
	non_admin_maintainers = [maintainers[idx] | not maintainers[idx] in admins]
	complete_list = array.concat(admins, non_admin_maintainers)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
		maintainers_response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
		admins_response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		maintainers_response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		admins_response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators."
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		admins_response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository collaborators for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		maintainers_response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "GitHub is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
		codes = [401, 404, 500, 200, 301, 302]
		not admins_response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [admins_response.status_code, admins_response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
		codes = [401, 404, 500, 200, 301, 302]
		not maintainers_response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [maintainers_response.status_code, maintainers_response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := complete_list
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		denial_list_str := concat(", ", denial_list)
		not policy_name in exception_list
		msg := sprintf("Maintainer and Admin access of Github Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		denial_list_str := concat(", ", denial_list)
		policy_name in exception_list
		msg := sprintf("Maintainer and Admin access of Github Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	267: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "collaborators"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository collaborators for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		admins = [response.body[i].login | response.body[i].role_name == "admin"]
		total_users = count(response.body[i])
		admin_users = count(admins)
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		not policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		admins = [response.body[i].login | response.body[i].role_name == "admin"]
		total_users = count(response.body[i])
		admin_users = count(admins)
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	268: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	token = input.metadata.ssd_secret.github.token
	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "activity?time_period=quarter&activity_type=push&per_page=500"]

	collaborators_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "collaborators"]
	collaborators_url = concat("/",collaborators_components)

	collaborators = {
		"method": "GET",
		"url": collaborators_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	coll_resp = http.send(collaborators)

	responsesplit = coll_resp.body

	coll_users = {coluser |
		some i
		coluser = responsesplit[i];
		coluser.role_name != "admin"
		coluser.type == "User"
	}

	request_url = concat("/",request_components)

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	resp = http.send(request)
	link_1 = split(resp.headers.link[0], " ")[0]
	decoded_link_1 = replace(link_1, "\u003e;", "")
	decoded_link_2 = replace(decoded_link_1, "\u003c", "")
	link_request = {
		"method": "GET",
		"url": decoded_link_2,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	resp2 =  http.send(link_request)

	evnt_users = resp.body

	evnt_logins = {user |
		some i
		user = evnt_users[i];
		user.actor.type == "User"
	}

	login_values[login] {
		user = evnt_logins[_]
		login = user.actor.login
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		allusers = coll_users[_]
		eventlogins = evnt_logins[_]
		allusers.login == login_values[_]
		not policy_name in exception_list
		msg := sprintf("Access of Github repository %s has been granted to users %v who have no activity from last three months", [input.metadata.github_repo,login_values[_]])
		sugg := "Adhere to the company policy and revoke access of inactive members"
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		allusers = coll_users[_]
		eventlogins = evnt_logins[_]
		allusers.login == login_values[_]
		policy_name in exception_list
		msg := sprintf("Access of Github repository %s has been granted to users %v who have no activity from last three months", [input.metadata.github_repo,login_values[_]])
		sugg := "Adhere to the company policy and revoke access of inactive members"
		error := ""
		alertStatus := "exception"
	}`,

	269: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"dependency-graph/sbom"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := "Unauthorized to check repository configuration due to Bad Credentials."
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := "Repository not found or SBOM could not be fetched."
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration. Also, kindly verify if dependency tracking is enabled for the repository."
		msg := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "GitHub is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.body.sbom = "" 
		error := sprintf("The SBOM could not be fetched, hence Centralized package manager settings Policy cannot be validated.", [input.metadata.repository])
		sugg := "Please make sure there are some packages in the GitHub Repository."
		msg := ""
		alertStatus := "error"
	}

	default pkg_without_version = []

	pkg_without_version = [pkg2.name | pkg2 := response.body.sbom.packages[_]
								pkg2.name != response.body.sbom.name
								not startswith(pkg2.name, "actions:")
								pkg2.versionInfo == ""]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(pkg_without_version) != 0
		not policy_name in exception_list
		msg := sprintf("The GitHub repository %v/%v exhibits packages with inadequate versioning.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and mandate proper tagging and versioning for packages of %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		count(pkg_without_version) != 0
		policy_name in exception_list
		msg := sprintf("The GitHub repository %v/%v exhibits packages with inadequate versioning.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and mandate proper tagging and versioning for packages of %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	270: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"dependency-graph/sbom"]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository configurations for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := "Repository SBOM not found while trying to fetch Repository Configuration."
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration. Also, check if dependency mapping is enabled."
		error := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configurations for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.body.sbom = "" 
		error := sprintf("The SBOM could not be fetched for repository %v/%v, hence Centralized package manager settings Policy cannot be validated.", [input.metadata.owner, input.metadata.repository])
		sugg := "Please make sure there are some packages in the GitHub Repository."
		msg := ""
		alertStatus := "error"
	}

	default_pkg_list = []
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		pkg_list = [pkg.name | pkg := response.body.sbom.packages[_]
								pkg.name != response.body.sbom.name
								not startswith(pkg.name, "actions:")]

		count(pkg_list) == 0
		not policy_name in exception_list
		msg := sprintf("The GitHub repository %v/%v lacks the necessary configuration files for package managers.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and consider adding the necessary package manager configuration files to the GitHub repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		pkg_list = [pkg.name | pkg := response.body.sbom.packages[_]
								pkg.name != response.body.sbom.name
								not startswith(pkg.name, "actions:")]

		count(pkg_list) == 0
		policy_name in exception_list
		msg := sprintf("The GitHub repository %v/%v lacks the necessary configuration files for package managers.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and consider adding the necessary package manager configuration files to the GitHub repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	271: `
	package opsmx
	import future.keywords.in
	import data.strings

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	body := {
		"image": input.metadata.image,
		"imageTag": input.metadata.image_tag,
		"username": input.metadata.ssd_secret.imageCreds.username,
		"password": input.metadata.ssd_secret.imageCreds.password
	}

	request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/artifactSign"])

	request = {
		"method": "POST",
		"url": request_url,
		"body": body
	}

	response = http.send(request) 

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.code == 500
		not policy_name in exception_list
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := "Kindly use only trusted artifacts in critical environments. To validate trust, the signature must be associated with the artifact."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.code == 500
		policy_name in exception_list
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := "Kindly use only trusted artifacts in critical environments. To validate trust, the signature must be associated with the artifact."
		error := ""
		alertStatus := "exception"
	}`,

	272: `
	package opsmx

	import future.keywords.in
	import data.strings

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default signed_imge_sha = ""

	body := {
		"image": input.metadata.image,
			"imageTag": input.metadata.image_tag,
			"username": input.metadata.ssd_secret.imageCreds.username,
			"password": input.metadata.ssd_secret.imageCreds.password
	}

	request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/artifactSign"])

	request = {
		"method": "POST",
		"url": request_url,
		"body": body
	}

	response = http.send(request) 

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.code == 500
		not policy_name in exception_list
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := ""
		error := "Kindly use only trusted artifacts in critical environments. To validate trust, the signature of deployed artifact must be associated."
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.code == 500
		policy_name in exception_list
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := ""
		error := "Kindly use only trusted artifacts in critical environments. To validate trust, the signature of deployed artifact must be associated."
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 200
		signed_image_sha = response.body.imageSha
		signed_image_sha != input.metadata.image_sha
		not policy_name in exception_list
		msg := "Artifact SHA deployed in Cloud does not match with Signed Artifact SHA."
		sugg :="Kindly use only trusted artifacts in critical environments. To validate trust, the signature of deployed artifact must be associated."
		error := ""
		alertStatus := ""
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code == 200
		signed_image_sha = response.body.imageSha
		signed_image_sha != input.metadata.image_sha
		policy_name in exception_list
		msg := "Artifact SHA deployed in Cloud does not match with Signed Artifact SHA."
		sugg :="Kindly use only trusted artifacts in critical environments. To validate trust, the signature of deployed artifact must be associated."
		error := ""
		alertStatus := "exception"
	}`,

	273: `sample script`,

	274: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default secrets_count = 0

	request_url = concat("",[input.metadata.toolchain_addr,"api/", "v1/", "scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeScanResult.json"]) {
		input.metadata.source_code_path != ""
	}
		
	complete_url = concat("", [request_url, file_name, "&scanOperation=codeSecretScan"])
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	high_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "HIGH"]
	secrets_count = count(high_severity_secrets)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in high_severity_secrets
		not i in exception_list
		title := sprintf("High Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in high_severity_secrets
		i in exception_list
		title := sprintf("High Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "exception"
		exception_cause := i
	}`,

	275: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default secrets_count = 0

	request_url = concat("",[input.metadata.toolchain_addr,"api/", "v1/", "scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeScanResult.json"]) {
		input.metadata.source_code_path != ""
	}
		
	complete_url = concat("", [request_url, file_name, "&scanOperation=codeSecretScan"])
		
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	critical_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "CRITICAL"]
	secrets_count = count(critical_severity_secrets)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in critical_severity_secrets
		not i in exception_list
		title := sprintf("Critical Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in critical_severity_secrets
		i in exception_list
		title := sprintf("Critical Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "exception"
		exception_cause := i
	}`,

	276: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default secrets_count = 0

	request_url = concat("",[input.metadata.toolchain_addr,"api/", "v1/", "scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeScanResult.json"]) {
		input.metadata.source_code_path != ""
	}
		
	complete_url = concat("", [request_url, file_name, "&scanOperation=codeSecretScan"])
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	medium_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "MEDIUM"]
	secrets_count = count(medium_severity_secrets)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		not i in exception_list
		title := sprintf("Medium Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		i in exception_list
		title := sprintf("Medium Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "exception"
		exception_cause := i
	}`,

	277: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default secrets_count = 0

	request_url = concat("",[input.metadata.toolchain_addr,"api/", "v1/", "scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeScanResult.json"]) {
		input.metadata.source_code_path != ""
	}
		
	complete_url = concat("", [request_url, file_name, "&scanOperation=codeSecretScan"])
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	low_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "LOW"]
	secrets_count = count(low_severity_secrets)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in low_severity_secrets
		not i in exception_list
		title := sprintf("Low Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in low_severity_secrets
		i in exception_list
		title := sprintf("Low Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "exception"
		exception_cause := i
	}`,

	278: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default secrets_count = 0

	default image_name = ""

	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}

	request_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")
	filename_components = [image_sha, "imageSecretScanResult.json"]
	filename = concat("-", filename_components)

	complete_url = concat("", [request_url, filename, "&scanOperation=imageSecretScan"])

	request = {
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	high_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "HIGH"]
	secrets_count = count(high_severity_secrets)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in high_severity_secrets
		not i in exception_list
		title := sprintf("High Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in high_severity_secrets
		i in exception_list
		title := sprintf("High Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		exception_cause := i
		alertStatus := "exception"
	}`,

	279: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]
	default secrets_count = 0

	default image_name = ""

	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}

	request_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")
	filename_components = [image_sha, "imageSecretScanResult.json"]
	filename = concat("-", filename_components)

	complete_url = concat("", [request_url, filename, "&scanOperation=imageSecretScan"])

	request = {
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	critical_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "CRITICAL"]
	secrets_count = count(critical_severity_secrets)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in critical_severity_secrets
		not i in exception_list
		title := sprintf("Critical Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in critical_severity_secrets
		i in exception_list
		title := sprintf("Critical Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		exception_cause := i
		alertStatus := "exception"
	}`,

	280: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]
	default secrets_count = 0

	default image_name = ""

	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}

	request_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")
	filename_components = [image_sha, "imageSecretScanResult.json"]
	filename = concat("-", filename_components)

	complete_url = concat("", [request_url, filename, "&scanOperation=imageSecretScan"])

	request = {
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	medium_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "MEDIUM"]
	secrets_count = count(medium_severity_secrets)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		not i in exception_list
		title := sprintf("Medium Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		i in exception_list
		title := sprintf("Medium Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		exception_cause := i
		alertStatus := "exception"
	}`,

	281: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]
	default secrets_count = 0

	default image_name = ""

	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}

	request_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")
	filename_components = [image_sha, "imageSecretScanResult.json"]
	filename = concat("-", filename_components)

	complete_url = concat("", [request_url, filename, "&scanOperation=imageSecretScan"])

	request = {
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	low_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "LOW"]
	secrets_count = count(low_severity_secrets)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in low_severity_secrets
		not i in exception_list
		title := sprintf("Low Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in low_severity_secrets
		i in exception_list
		title := sprintf("Low Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		exception_cause := i
		alertStatus := "exception"
	}`,

	282: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "high"
	default findings_count = 0

	chart_name = input.metadata.chartName
	chart_version = input.metadata.chartVersion
	helm_tool = input.metadata.helmTool

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"]	)
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings = response.body.helmAnalysis

	findings_count = count(findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		not rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	283: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "critical"
	default findings_count = 0

	chart_name = input.metadata.chartName
	chart_version = input.metadata.chartVersion
	helm_tool = input.metadata.helmTool

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"]	)
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings = response.body.helmAnalysis

	findings_count = count(findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		not rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	284: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "medium"
	default findings_count = 0

	chart_name = input.metadata.chartName
	chart_version = input.metadata.chartVersion
	helm_tool = input.metadata.helmTool

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"]	)
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings = response.body.helmAnalysis

	findings_count = count(findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		not rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	285: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "low"
	default findings_count = 0

	chart_name = input.metadata.chartName
	chart_version = input.metadata.chartVersion
	helm_tool = input.metadata.helmTool

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"]	)
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=findings_", chart_name, "_", chart_version, "_", helm_tool, "_", severity, ".json&scanOperation=helmscan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings = response.body.helmAnalysis

	findings_count = count(findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		not rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		rule_id := findings[i].RuleID
		rule_id in exception_list
		tite := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
		msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, findings[i].TargetResources])
		error := ""
		sugg := findings[i].Resolution
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}`,

	286: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]


	default allow = false
	default private_repo = ""

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url, "api/v4/projects/", input.metadata.gitlab_project_id])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
		error := "Repository not found while trying to fetch Repository Configuration."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Github upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.visibility != "private"
		not policy_name in exception_list
		msg := sprintf("Gitlab Project %v is publically visible.", [input.metadata.repository])
		sugg := "Kindly adhere to security standards and change the visibility of the repository to private."
		error := ""
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.visibility != "private"
		policy_name in exception_list
		msg := sprintf("Gitlab Project %v is publically visible.", [input.metadata.repository])
		sugg := "Kindly adhere to security standards and change the visibility of the repository to private."
		error := ""
		alertStatus := "exception"
	}`,

	287: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false
	default number_of_merges = 0
	default merges_unreviewed = []
	default merges_reviewed_by_bots = []
	default merges_reviewed_by_author = []

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/merge_requests?state=merged&order_by=created_at"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	number_of_merges = count(response.body)
	merges_unreviewed = [response.body[i].iid | count(response.body[i].reviewers) == 0]
	merges_reviewed_by_bots = [response.body[i].iid | contains(response.body[i].reviewers[j].username, "bot")]
	merges_reviewed_by_author = [response.body[i].iid | response.body[i].reviewers[j].username == response.body[i].author.username]

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": "", "alertStatus": alertStatus}]{
		count(merges_reviewed_by_bots) > 0
		not policy_name in exception_list
		msg := sprintf("Merge Request with bot user as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_bots])
		sugg := "Adhere to security standards by restricting reviews by bot users."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": policy_name, "alertStatus": alertStatus}]{
		count(merges_reviewed_by_bots) > 0
		policy_name in exception_list
		msg := sprintf("Merge Request with bot user as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_bots])
		sugg := "Adhere to security standards by restricting reviews by bot users."
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": "", "alertStatus": alertStatus}]{
		count(merges_reviewed_by_author) > 0
		not policy_name in exception_list
		msg := sprintf("Merge Request with Author as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_author])
		sugg := "Adhere to security standards by restricting reviews by authors."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": policy_name, "alertStatus": alertStatus}]{
		count(merges_reviewed_by_author) > 0
		policy_name in exception_list
		msg := sprintf("Merge Request with Author as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_author])
		sugg := "Adhere to security standards by restricting reviews by authors."
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": "", "alertStatus": alertStatus}]{
		count(merges_unreviewed) > 0
		not policy_name in exception_list
		msg := sprintf("Unreviewed Merge Requests found to be merged. Merge Request ID: %v.",[merges_unreviewed])
		sugg := "Adhere to security standards by restricting merges without reviews."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": policy_name, "alertStatus": alertStatus}]{
		count(merges_unreviewed) > 0
		policy_name in exception_list
		msg := sprintf("Unreviewed Merge Requests found to be merged. Merge Request ID: %v.",[merges_unreviewed])
		sugg := "Adhere to security standards by restricting merges without reviews."
		error := ""
		alertStatus := "exception"
	}`,

	288: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/repository/branches/", input.metadata.branch])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code in [200]
		response.body.protected == false
		not policy_name in exception_list
		msg := sprintf("Branch %v of Gitlab repository %v is not protected by a branch protection policy.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Gitlab repository.",[input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code in [200]
		response.body.protected == false
		policy_name in exception_list
		msg := sprintf("Branch %v of Gitlab repository %v is not protected by a branch protection policy.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Gitlab repository.",[input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	289: `
	package opsmx

	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/members"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository members due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get repository members."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository members."
		error := "Mentioned branch for Repository not found while trying to fetch repository members."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := [response.body[i].username | response.body[i].access_level == 50]
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		not policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Gitlab Repository is granted to bot users. \n Number of bot users having owner access: %v. \n Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Gitlab Repository is granted to bot users. \n Number of bot users having owner access: %v. \n Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}`,

	290: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/repository/files/SECURITY.md?ref=", input.metadata.branch])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		not policy_name in exception_list
		msg := sprintf("SECURITY.md file not found in branch %v of repository %v.", [input.metadata.branch, input.metadata.repository])
		sugg := "Adhere to security standards and configure SECURITY.md file in the repository."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code == 404
		policy_name in exception_list
		msg := sprintf("SECURITY.md file not found in branch %v of repository %v.", [input.metadata.branch, input.metadata.repository])
		sugg := "Adhere to security standards and configure SECURITY.md file in the repository."
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}`,

	291: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false

	request_components = [input.metadata.ssd_secret.gitlab.url,"api/v4/user"]

	request_url = concat("",request_components)

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.two_factor_enabled == false
		not policy_name in exception_list
		msg := sprintf("Gitlab Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enabling 2FA for users of %s organisation.",[input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.two_factor_enabled == false
		policy_name in exception_list
		msg := sprintf("Gitlab Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enabling 2FA for users of %s organisation.",[input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}`,

	292: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/hooks"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository webhook configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get webhook configurations."
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read webhook configuration."
		error := "Mentioned branch for Repository not found while trying to fetch webhook configuration."
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "active"
	}

	default ssl_disabled_hooks = []
	ssl_disabled_hooks = [response.body[i].id | response.body[i].enable_ssl_verification == false]

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": "", "alertStatus": alertStatus}]{
		count(ssl_disabled_hooks) > 0
		not policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": policy_name, "alertStatus": alertStatus}]{
		count(ssl_disabled_hooks) > 0
		policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		alertStatus := "exception"
	}`,

	295: `
	package opsmx
	import future.keywords.in

	default allow = false
	default private_repo = ""
	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)


	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.is_private == false
		not policy_name in exception_list
		msg := sprintf("Repository %v/%v is found to be publically accessible.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to security standards by restricting public accessibility of repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.is_private == false
		policy_name in exception_list
		msg := sprintf("Repository %v/%v is found to be publically accessible.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to security standards by restricting public accessibility of repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	296: `
	package opsmx
	import future.keywords.in

	default allow = false

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, "policies/branch-restrictions"]

	request_url = concat("/",request_components)

	headers = {
	  "Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
  		input.metadata.ssd_secret.bitbucket.isBasicAuth
  		username = input.metadata.ssd_secret.bitbucket.user
  		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
  		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
    		encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	abc = [user |
		user = response.body.values[i];
		user.kind == "require_approvals_to_merge"
		user.pattern = input.metadata.branch 
	]

	reviewers = abc[_].value

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	error := "401 Unauthorized."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	error := "Repo name or Organisation is incorrect."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Bitbucket is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 301, 302]
	not response.status_code in codes
	msg := "Unable to fetch repository branch protection policy configuration."
	error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
	sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	abc[_].value <= 1
	msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the Bitbucket", [input.metadata.branch])
	sugg := "Adhere to the company policy by establishing the correct minimum reviewers for Bitbucket"
	error := ""
	}`,

	297: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "branch-restrictions"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	branch_protect = [response.body.values[i]| response.body.values[i].type == "branchrestriction"]

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check branch protection policy configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository branch protection policy configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.size == 0
		not policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.size == 0
		policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(branch_protect) == 0
		not policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		count(branch_protect) == 0
		policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	298: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "branch-restrictions?kind=delete"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}


	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check branch protection policy configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository branch protection policy configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.size == 0
		not policy_name in exception_list
		msg := sprintf("Branch Protection Policy to prevent deletion of branches is not set for repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		error := ""
		sugg := sprintf("Kindly introduce branch protection policy to prevent deletion of branches to repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.size == 0
		policy_name in exception_list
		msg := sprintf("Branch Protection Policy to prevent deletion of branches is not set for repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		error := ""
		sugg := sprintf("Kindly introduce branch protection policy to prevent deletion of branches to repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		alertStatus := "exception"
	}`,

	299: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "branch-restrictions?kind=restrict_merges"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	admins= [response.body.values[i].users[_].display_name | response.body.values[i].kind == "restrict_merges"]

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check branch protection policy configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository branch protection policy configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.body.size == 0
		not policy_name in exception_list
		msg := sprintf("Branch Protection Policy to restrict merge operations to limited users is not set for repository %v/%v. This indicates that all users can perform merge operations.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and configure restricted merge operations for %v/%v Repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.body.size == 0
		policy_name in exception_list
		msg := sprintf("Branch Protection Policy to restrict merge operations to limited users is not set for repository %v/%v. This indicates that all users can perform merge operations.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and configure restricted merge operations for %v/%v Repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := admins
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		denial_list_str := concat(", ", denial_list)
		not policy_name in exception_list
		msg := sprintf("Maintainer and Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		denial_list_str := concat(", ", denial_list)
		policy_name in exception_list
		msg := sprintf("Maintainer and Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}`,

	300: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/workspaces", input.metadata.owner, "permissions/repositories", input.metadata.repository]
	request_url = concat("/",request_components)
	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}
	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}
	response = http.send(request)

	allow {
	response.status_code = 200
	}

	admins = [response.body.values[i].user.display_name| response.body.values[i].permission == "admin"]

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository collaborators.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository collaborators.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking collaborators for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository collaborators."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository collaborators.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := admins
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		not policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions as repository admins: %v. Name of bots having permissions as repository admins: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions as repository admins: %v. Name of bots having permissions as repository admins: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}`,

	301: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/workspaces", input.metadata.owner, "permissions"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check organisation members for organisation %s due to Bad Credentials.", [input.metadata.owner])
		error := sprintf("401 Unauthorized. Unauthorized to check organisation members for organisation %s due to Bad Credentials.", [input.metadata.owner])
		sugg := "Kindly check the access token. It must have enough permissions to get organisation members."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Organisation members %s not found while trying to fetch organisation members.", [input.metadata.owner])
		sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation members."
		error := sprintf("Organisation %s not found while trying to fetch organisation members.", [input.metadata.owner])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking organisation members for organisation %s.", [input.metadata.owner])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch organisation members."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch organisation members.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	admins = [response.body.values[i].user.display_name | response.body.values[i].permission == "owner"]

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := admins
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		not policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Bitbucket Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Bitbucket Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}`,

	302: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]


	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "branch-restrictions?kind=allow_auto_merge_when_builds_pass"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}


	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check branch protection policy configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository branch protection policy configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.size != 0
		not policy_name in exception_list
		msg := sprintf("Branch Protection Policy allows automatic merging of code branch upon build pass conditions for repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		error := ""
		sugg := sprintf("Kindly restrict branch protection policy that allows automatic merge of branches to repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.size != 0
		policy_name in exception_list
		msg := sprintf("Branch Protection Policy allows automatic merging of code branch upon build pass conditions for repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		error := ""
		sugg := sprintf("Kindly restrict branch protection policy that allows automatic merge of branches to repository %s/%s.", [input.metadata.owner, input.metadata.repository]) 
		alertStatus := "exception"
	}`,

	303: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/workspaces", input.metadata.owner, "permissions/repositories", input.metadata.repository]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	admin = [entry | 
		entry = response.body.values[i]; 
		entry.type == "repository_permission"
		entry.permission == "admin"]

	admin_users = count(admin)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository permissions configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository permissions Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository permissions configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository permissions Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository permissions configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository permissions configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code in [200]
		admin_users <= 1
		not policy_name in exception_list
		msg := sprintf("Organisation/Worskspace %v should have more than one owner so access to the code is not jeopardized.",[input.metadata.owner])
		sugg := "To reduce the attack surface it is recommended to have more than 1 admin of an organization or workspace."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code in [200]
		admin_users <= 1
		policy_name in exception_list
		msg := sprintf("Organisation/Worskspace %v should have more than one owner so access to the code is not jeopardized.",[input.metadata.owner])
		sugg := "To reduce the attack surface it is recommended to have more than 1 admin of an organization or workspace."
		error := ""
		alertStatus := "exception"
	}`,

	304: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/workspaces", input.metadata.owner, "permissions/repositories",input.metadata.repository]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	admin = [user |
		user = response.body.values[i];
		user.type == "repository_permission"
		user.permission == "admin"
	]

	admin_users = count(admin)

	all = [user |
		user = response.body.values[i];
		user.type == "repository_permission"
		user.user.type == "user"
	]

	total_users = count(all)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository permissions configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository permissions Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository permissions configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository permissions Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository permissions configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository permissions configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		not policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v Bitbucket repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v Bitbucket repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	305: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "hooks"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	webhook = response.body.values

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check webhooks for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check webhooks for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository webhooks configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository webhooks Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhooks configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository webhooks Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking webhooks configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository webhooks configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository webhooks configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(webhook) == 0
		not policy_name in exception_list
		msg = sprintf("Webhooks are not configured for the repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error = ""
		sugg = "Kindly enable webhooks for the repository rovide secure way of consuming events from source repository." 
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		count(webhook) == 0
		policy_name in exception_list
		msg = sprintf("Webhooks are not configured for the repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error = ""
		sugg = "Kindly enable webhooks for the repository rovide secure way of consuming events from source repository."  
		alertStatus := "exception"
	}`,

	306: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]


	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "hooks"]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	certs_check = response.body.values[_].skip_cert_verification

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check webhooks for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check webhooks for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository webhooks configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository webhooks Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhooks configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository webhooks Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking webhooks configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository webhooks configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository webhooks configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		certs_check == false
		not policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		certs_check == false
		policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		alertStatus := "exception"
	}`,

	307: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "High"
	default findings_count = 0
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_snyk.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_snyk.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=snykcodescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=snykcodescan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	findings_count = count([response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["High", "high"]])
	findings = [response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["High", "high"]]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		not findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity %v",[findings[i].ruleName, findings[i].ruleMessage])
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the high severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the high severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].ruleName
		alertStatus := "exception"
	}`,

	308: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "Medium"
	default findings_count = 0
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_snyk.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_snyk.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=snykcodescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=snykcodescan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	findings_count = count([response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["Medium", "medium"]])
	findings = [response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["Medium", "medium"]]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		not findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the medium severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the medium severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].ruleName
		alertStatus := "exception"
	}`,

	309: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "Low"
	default findings_count = 0
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_snyk.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_snyk.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=snykcodescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=snykcodescan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	findings_count = count([response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["Low", "low"]])
	findings = [response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["Low", "low"]]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		not findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName], findings[i].ruleMessage)
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the medium severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the medium severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].ruleName
		alertStatus := "exception"
	}`,

	310: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		license_count == 0
		not policy_name in exception_list
		title := "Code License Scan: No license found."
		msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
		sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		license_count == 0
		policy_name in exception_list
		title := "Code License Scan: No license found."
		msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
		sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
		error := ""
		alertStatus := "exception"
	}`,

	311: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default low_severity_licenses = []
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [results[idx1].Licenses[idx2] | count(results[idx1].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Code License Scan: No license found."
			msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with repository %v:%v.", [input.metadata1.owner, input.metadata1.repository])
			alertStatus := "error"
	}

	low_severity_licenses = [licenses[idx] | licenses[idx].Severity == "LOW"]
	low_severity_licenses_with_exception = [low_severity_licenses[idx] | low_severity_licenses[idx].Name in exception_list]
	low_severity_licenses_without_exception = [low_severity_licenses[idx] | not low_severity_licenses[idx].Name in exception_list] 

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(low_severity_licenses_without_exception) > 0
			some i in low_severity_licenses_without_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Code License Scan: Low Severity License: %v found to be associated with repository %v:%v.",[i.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(low_severity_licenses_with_exception) > 0
			some j in low_severity_licenses_with_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Code License Scan: Low Severity License: %v found to be associated with repository %v:%v.",[j.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	312: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default medium_severity_licenses = []
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [results[idx1].Licenses[idx2] | count(results[idx1].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Code License Scan: No license found."
			msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with repository %v:%v.", [input.metadata1.owner, input.metadata1.repository])
			alertStatus := "error"
	}

	medium_severity_licenses = [licenses[idx] | licenses[idx].Severity == "MEDIUM"]
	medium_severity_licenses_with_exception = [medium_severity_licenses[idx] | medium_severity_licenses[idx].Name in exception_list]
	medium_severity_licenses_without_exception = [medium_severity_licenses[idx] | not medium_severity_licenses[idx].Name in exception_list] 

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(medium_severity_licenses_without_exception) > 0
			some i in medium_severity_licenses_without_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Code License Scan: Medium Severity License: %v found to be associated with repository %v:%v.",[i.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(medium_severity_licenses_with_exception) > 0
			some j in medium_severity_licenses_with_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Code License Scan: Medium Severity License: %v found to be associated with repository %v:%v.",[j.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	313: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default high_severity_licenses = []

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [results[idx1].Licenses[idx2] | count(results[idx1].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Code License Scan: No license found."
			msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with repository %v:%v.", [input.metadata1.owner, input.metadata1.repository])
			alertStatus := "error"
	}

	high_severity_licenses = [licenses[idx] | licenses[idx].Severity == "HIGH"]
	high_severity_licenses_with_exception = [high_severity_licenses[idx] | high_severity_licenses[idx].Name in exception_list]
	high_severity_licenses_without_exception = [high_severity_licenses[idx] | not high_severity_licenses[idx].Name in exception_list] 

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(high_severity_licenses_without_exception) > 0
			some i in high_severity_licenses_without_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Code License Scan: High Severity License: %v found to be associated with repository %v:%v.",[i.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(high_severity_licenses_with_exception) > 0
			some j in high_severity_licenses_with_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Code License Scan: High Severity License: %v found to be associated with repository %v:%v.",[j.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	314: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default critical_severity_licenses = []
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [results[idx1].Licenses[idx2] | count(results[idx1].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Code License Scan: No license found."
			msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with repository %v:%v.", [input.metadata1.owner, input.metadata1.repository])
			alertStatus := "error"
	}

	critical_severity_licenses = [licenses[idx] | licenses[idx].Severity == "CRITICAL"]
	critical_severity_licenses_with_exception = [critical_severity_licenses[idx] | critical_severity_licenses[idx].Name in exception_list]
	critical_severity_licenses_without_exception = [critical_severity_licenses[idx] | not critical_severity_licenses[idx].Name in exception_list] 

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(critical_severity_licenses_without_exception) > 0
			some i in critical_severity_licenses_without_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Code License Scan: Critical Severity License: %v found to be associated with repository %v:%v.",[i.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(critical_severity_licenses_with_exception) > 0
			some j in critical_severity_licenses_with_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Code License Scan: Critical Severity License: %v found to be associated with repository %v:%v.",[j.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	315: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")
	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
		    not policy_name in exception_list
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := ""
			alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
			license_count == 0
			policy_name in exception_list
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := ""
			alertStatus := "exception"
	}`,

	316: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default low_severity_licenses = []

	image_sha = replace(input.metadata.image_sha, ":", "-")
	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Artifact License Scan: No license found."
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with artifact %v.", [input.metadata.image])
			alertStatus := "error"
	}

	low_severity_licenses = [licenses[idx] | licenses[idx].Severity == "LOW"]
	low_severity_licenses_with_exception = [low_severity_licenses[idx] | low_severity_licenses[idx].Name in exception_list]
	low_severity_licenses_without_exception = [low_severity_licenses[idx] | not low_severity_licenses[idx].Name in exception_list] 


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(low_severity_licenses_without_exception) > 0
			some i in low_severity_licenses_without_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Artifact License Scan: Low Severity License: %v found to be associated with package %v in artifact %v:%v.",[i.Name, i.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(low_severity_licenses_with_exception) > 0
			some j in low_severity_licenses_with_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Artifact License Scan: Low Severity License: %v found to be associated with package %v in artifact %v:%v.",[j.Name, j.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	317: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default medium_severity_licenses = []

	image_sha = replace(input.metadata.image_sha, ":", "-")
	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Artifact License Scan: No license found."
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with artifact %v.", [input.metadata.image])
			alertStatus := "error"
	}

	medium_severity_licenses = [licenses[idx] | licenses[idx].Severity == "MEDIUM"]
	medium_severity_licenses_with_exception = [medium_severity_licenses[idx] | medium_severity_licenses[idx].Name in exception_list]
	medium_severity_licenses_without_exception = [medium_severity_licenses[idx] | not medium_severity_licenses[idx].Name in exception_list] 


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(medium_severity_licenses_without_exception) > 0
			some i in medium_severity_licenses_without_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Artifact License Scan: Medium Severity License: %v found to be associated with package %v in artifact %v:%v.",[i.Name, i.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(medium_severity_licenses_with_exception) > 0
			some j in medium_severity_licenses_with_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Artifact License Scan: Medium Severity License: %v found to be associated with package %v in artifact %v:%v.",[j.Name, j.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	318: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default high_severity_licenses = []

	image_sha = replace(input.metadata.image_sha, ":", "-")
	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Artifact License Scan: No license found."
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with artifact %v.", [input.metadata.image])
			alertStatus := "error"
	}

	high_severity_licenses = [licenses[idx] | licenses[idx].Severity == "HIGH"]
	high_severity_licenses_with_exception = [high_severity_licenses[idx] | high_severity_licenses[idx].Name in exception_list]
	high_severity_licenses_without_exception = [high_severity_licenses[idx] | not high_severity_licenses[idx].Name in exception_list] 


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(high_severity_licenses_without_exception) > 0
			some i in high_severity_licenses_without_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Artifact License Scan: High Severity License: %v found to be associated with package %v in artifact %v:%v.",[i.Name, i.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(high_severity_licenses_with_exception) > 0
			some j in high_severity_licenses_with_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Artifact License Scan: High Severity License: %v found to be associated with package %v in artifact %v:%v.",[j.Name, j.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	319: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default critical_severity_licenses = []

	image_sha = replace(input.metadata.image_sha, ":", "-")
	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Artifact License Scan: No license found."
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with artifact %v.", [input.metadata.image])
			alertStatus := "error"
	}

	critical_severity_licenses = [licenses[idx] | licenses[idx].Severity == "CRITICAL"]
	critical_severity_licenses_with_exception = [critical_severity_licenses[idx] | critical_severity_licenses[idx].Name in exception_list]
	critical_severity_licenses_without_exception = [critical_severity_licenses[idx] | not critical_severity_licenses[idx].Name in exception_list] 


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(critical_severity_licenses_without_exception) > 0
			some i in critical_severity_licenses_without_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Artifact License Scan: Critical Severity License: %v found to be associated with package %v in artifact %v:%v.",[i.Name, i.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(critical_severity_licenses_with_exception) > 0
			some j in critical_severity_licenses_with_exception
			title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Artifact License Scan: Critical Severity License: %v found to be associated with package %v in artifact %v:%v.",[j.Name, j.PkgName, input.metadata.image, input.metadata.image_tag])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}`,

	320: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default url_count = 0
	default malicious_urls = []
	default malicious_urls_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_virustotal_url_scan.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_virustotal_url_scan.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=virustotalscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=virustotalscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.summaryResult
	repo_name := response.body.repoName
	branch := response.body.branch

	malicious_urls := [results[idx] | results[idx].malicious > 0]

	malicious_urls_count = count(malicious_urls)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			malicious_urls_count > 0
			some i
			not malicious_urls[i].url in exception_list
			title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [malicious_urls[i].url, repo_name, branch])
			msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[malicious_urls[i].url, repo_name, branch, malicious_urls[i].harmless, malicious_urls[i].malicious, malicious_urls[i].malicious, malicious_urls[i].undetected, malicious_urls[i].timeout])
			sugg := "Suggest securing the webhook endpoints from malicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
			error := ""
			alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			malicious_urls_count > 0
			some i
			malicious_urls[i].url in exception_list
			title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [malicious_urls[i].url, repo_name, branch])
			msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[malicious_urls[i].url, repo_name, branch, malicious_urls[i].harmless, malicious_urls[i].malicious, malicious_urls[i].malicious, malicious_urls[i].undetected, malicious_urls[i].timeout])
			sugg := "Suggest securing the webhook endpoints from malicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
			error := ""
			exception_cause := malicious_urls[i].url
			alertStatus := "exception"
	}`,

	321: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default url_count = 0
	default suspicious_urls = []
	default suspicious_urls_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_virustotal_url_scan.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_virustotal_url_scan.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=virustotalscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=virustotalscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.summaryResult
	repo_name := response.body.repoName
	branch := response.body.branch

	suspicious_urls := [results[idx] | results[idx].suspicious > 0]

	suspicious_urls_count = count(suspicious_urls)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			suspicious_urls_count > 0
			some i
			not suspicious_urls[i].url in exception_list
			title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [suspicious_urls[i].url, repo_name, branch])
			msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[suspicious_urls[i].url, repo_name, branch, suspicious_urls[i].harmless, suspicious_urls[i].malicious, suspicious_urls[i].suspicious, suspicious_urls[i].undetected, suspicious_urls[i].timeout])
			sugg := "Suggest securing the webhook endpoints from suspicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
			error := ""
			alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			suspicious_urls_count > 0
			some i
			suspicious_urls[i].url in exception_list
			title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [suspicious_urls[i].url, repo_name, branch])
			msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[suspicious_urls[i].url, repo_name, branch, suspicious_urls[i].harmless, suspicious_urls[i].malicious, suspicious_urls[i].suspicious, suspicious_urls[i].undetected, suspicious_urls[i].timeout])
			sugg := "Suggest securing the webhook endpoints from suspicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
			error := ""
			exception_cause := suspicious_urls[i].url
			alertStatus := "exception"
	}`,

	322: `
	package opsmx

	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Define sensitive keywords to look for in the workflow
	sensitive_keywords = ["API_KEY", "SECRET_KEY", "PASSWORD", "TOKEN"]

	# Helper function to check if a string contains any sensitive keyword
	contains_sensitive_keyword(value) = true {
		some keyword in sensitive_keywords
		contains(value, keyword)
	}

	contains_sensitive_keyword(_) = false

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if any step contains hardcoded sensitive data
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check the run field for hardcoded sensitive data
		step.run
		contains_sensitive_keyword(step.run)
		not policy_name in exception_list

		msg := sprintf("Hardcoded sensitive data found in step %s of job %s in workflow %s.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Reference sensitive data using GitHub Secrets instead of hardcoding them in the workflow."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check the run field for hardcoded sensitive data
		step.run
		contains_sensitive_keyword(step.run)
		policy_name in exception_list

		msg := sprintf("Hardcoded sensitive data found in step %s of job %s in workflow %s.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Reference sensitive data using GitHub Secrets instead of hardcoding them in the workflow."
		error := ""
		alertStatus := "exception"
	}`,

	323: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Define a list of approved actions and their versions
	approved_actions = {
		"actions/checkout": "v2",
		"actions/setup-node": "v2",
		"docker/build-push-action": "v2",
		"docker/login-action": "v1"
		# Add more approved actions and their versions here
	}

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if the actions used in the workflow are approved
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]
		
		# Check if the step uses an action
		step.uses
		split_step := split(step.uses, "@")
		action_name := split_step[0]
		action_version := split_step[1]
		
		# Ensure the action is in the approved list
		not approved_actions[action_name] == action_version
		not policy_name in exception_list
		msg := sprintf("Action %v@%v is not from an approved source or version.", [action_name, action_version])
		sugg := "Update the action to an approved version listed in the policy, or contact the repository owner to approve the current version."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]
		
		# Check if the step uses an action
		step.uses
		split_step := split(step.uses, "@")
		action_name := split_step[0]
		action_version := split_step[1]
		
		# Ensure the action is in the approved list
		not approved_actions[action_name] == action_version
		policy_name in exception_list
		msg := sprintf("Action %v@%v is not from an approved source or version.", [action_name, action_version])
		sugg := "Update the action to an approved version listed in the policy, or contact the repository owner to approve the current version."
		error := ""
		alertStatus := "exception"
	}`,

	324: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Define a list of trusted sources for dependencies
	trusted_sources = [
		"https://registry.npmjs.org/",
		"https://pypi.org/simple/",
		"https://rubygems.org/"
		# Add more trusted sources here
	]

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if the dependencies are fetched from trusted sources
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check if the step installs dependencies
		step.run
		some dependency in split(step.run, "\n")
		contains(dependency, "install")

		# Verify the source of the dependency
		not is_trusted_source(dependency)
		not policy_name in exception_list
		msg := sprintf("Dependency fetched from untrusted source in step %s of job %s in workflow %s.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure all dependencies are fetched from trusted sources such as npm, PyPI, or RubyGems."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check if the step installs dependencies
		step.run
		some dependency in split(step.run, "\n")
		contains(dependency, "install")

		# Verify the source of the dependency
		not is_trusted_source(dependency)
		policy_name in exception_list
		msg := sprintf("Dependency fetched from untrusted source in step %s of job %s in workflow %s.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure all dependencies are fetched from trusted sources such as npm, PyPI, or RubyGems."
		error := ""
		alertStatus := "exception"
	}

	# Helper function to check if a dependency is from a trusted source
	is_trusted_source(dependency) {
		some trusted_source in trusted_sources
		contains(dependency, trusted_source)
	}`,

	325: `
	package opsmx

	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Define allowed branches and events
	allowed_branches = ["main", "master", "develop"]
	allowed_events = {"push", "pull_request"}

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if workflows are triggered on allowed branches and events
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		on := workflow.on

		# Check for disallowed branches in push triggers
		some branch in on.push.branches
		not branch in allowed_branches
		not policy_name in exception_list
		msg := sprintf("Workflow triggered on disallowed branch %v in push trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
		error := ""
		trigger := "branch"
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		on := workflow.on

		# Check for disallowed branches in push triggers
		some branch in on.push.branches
		not branch in allowed_branches
		policy_name in exception_list
		msg := sprintf("Workflow triggered on disallowed branch %v in push trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
		error := ""
		trigger := "branch"
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		on := workflow.on

		# Check for disallowed branches in pull_request triggers
		some branch in on.pull_request.branches
		not branch in allowed_branches
		not policy_name in exception_list
		msg := sprintf("Workflow triggered on disallowed branch %v in pull_request trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
		error := ""
		trigger := "branch"
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		on := workflow.on

		# Check for disallowed branches in pull_request triggers
		some branch in on.pull_request.branches
		not branch in allowed_branches
		policy_name in exception_list
		msg := sprintf("Workflow triggered on disallowed branch %v in pull_request trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
		error := ""
		trigger := "branch"
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		on := workflow.on

		# Check for disallowed events
		some event in object.keys(on)
		not event in allowed_events
		not policy_name in exception_list
		msg := sprintf("Workflow triggered on disallowed event %v in workflow %s.", [event, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure that the workflow is only triggered on allowed events: push or pull_request."
		error := ""
		trigger := "event"
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		on := workflow.on

		# Check for disallowed events
		some event in object.keys(on)
		not event in allowed_events
		policy_name in exception_list
		msg := sprintf("Workflow triggered on disallowed event %v in workflow %s.", [event, input.metadata.ssd_secret.github.workflowName])
		sugg := "Ensure that the workflow is only triggered on allowed events: push or pull_request."
		error := ""
		trigger := "event"
		alertStatus := "exception"
	}`,

	326: `
	package opsmx

	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Define allowed protocols
	allowed_protocols = ["https://", "ssh://"]

	# Helper function to check if a URL uses a secure protocol
	uses_secure_protocol(url) = true {
		some protocol in allowed_protocols
		startswith(url, protocol)
	}

	uses_secure_protocol(_) = false

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if all network communications use secure protocols
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check the run field for insecure protocols
		step.run
		some line in split(step.run, "\n")
		url := find_network_calls(line)
		not uses_secure_protocol(url)
		not policy_name in exception_list
		msg := sprintf("Insecure protocol used in step %s of job %s in workflow %s. URL: %v", [step.name, job.name, input.metadata.ssd_secret.github.workflowName, url])
		sugg := "Use secure protocols (https or ssh) for all network communications."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check the run field for insecure protocols
		step.run
		some line in split(step.run, "\n")
		url := find_network_calls(line)
		not uses_secure_protocol(url)
		policy_name in exception_list
		msg := sprintf("Insecure protocol used in step %s of job %s in workflow %s. URL: %v", [step.name, job.name, input.metadata.ssd_secret.github.workflowName, url])
		sugg := "Use secure protocols (https or ssh) for all network communications."
		error := ""
		alertStatus := "exception"
	}

	# Helper function to extract http URLs from a line of text
	find_http_url(line) = url {
		start := indexof(line, "http://")
		start != -1
		rest := substring(line, start, -1)
		end := indexof(rest, " ")
		end == -1
		url := substring(rest, 0, count(rest))
	} else {
		start := indexof(line, "http://")
		start != -1
		rest := substring(line, start, -1)
		end := indexof(rest, " ")
		end != -1
		url := substring(rest, 0, end)
	}

	# Helper function to extract ftp URLs from a line of text
	find_ftp_url(line) = url {
		start := indexof(line, "ftp://")
		start != -1
		rest := substring(line, start, -1)
		end := indexof(rest, " ")
		end == -1
		url := substring(rest, 0, count(rest))
	} else {
		start := indexof(line, "ftp://")
		start != -1
		rest := substring(line, start, -1)
		end := indexof(rest, " ")
		end != -1
		url := substring(rest, 0, end)
	}

	# Combined helper function to extract insecure URLs from a line of text
	find_network_calls(line) = url {
		url := find_http_url(line)
		url != ""
	} else {
		url := find_ftp_url(line)
		url != ""
	}`,

	327: `
	package opsmx

	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if each job has a timeout configured
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		jobs := workflow.jobs

		some job_name in jobs
		job := jobs[job_name]
		not job["timeout-minutes"]

		not policy_name in exception_list
		msg := sprintf("Job %s in workflow %s does not have a timeout configured.", [job_name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Configure a timeout for the job in the workflow file."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		jobs := workflow.jobs

		some job_name in jobs
		job := jobs[job_name]
		not job["timeout-minutes"]

		policy_name in exception_list
		msg := sprintf("Job %s in workflow %s does not have a timeout configured.", [job_name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Configure a timeout for the job in the workflow file."
		error := ""
		alertStatus := "exception"
	}

	# Check if each step has a timeout configured (if applicable)
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		jobs := workflow.jobs

		some job_name in jobs
		job := jobs[job_name]
		steps := job.steps

		some step_name in steps
		step := steps[step_name]
		not step["timeout-minutes"]
		not policy_name in exception_list
		msg := sprintf("Step %s in job %s of workflow %s does not have a timeout configured.", [step_name, job_name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Configure a timeout for the step in the workflow file."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		jobs := workflow.jobs

		some job_name in jobs
		job := jobs[job_name]
		steps := job.steps

		some step_name in steps
		step := steps[step_name]
		not step["timeout-minutes"]
		policy_name in exception_list
		msg := sprintf("Step %s in job %s of workflow %s does not have a timeout configured.", [step_name, job_name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Configure a timeout for the step in the workflow file."
		error := ""
		alertStatus := "exception"
	}`,

	328: `
	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository,"actions/permissions/workflow"] 

	request_url = concat("/", request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token])
		}
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := "Unauthorized to check repository configuration due to Bad Credentials."
		error := "401 Unauthorized."
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := "Repository not found while trying to fetch Repository Configuration."
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
		error := "Repo name or Organisation is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "GitHub is not reachable."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions == "write"
		not policy_name in exception_list
		msg := sprintf("Github actions workflow permissions are write permissions for %v/%v repository", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by the Github actions workflow permission should be read for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions == "write"
		policy_name in exception_list
		msg := sprintf("Github actions workflow permissions are write permissions for %v/%v repository", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by the Github actions workflow permission should be read for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}`,

	329: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]
	default count_blocker_issues = -1

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	blocker_issues = response.body.blockerIssues
	count_blocker_issues = count(blocker_issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_blocker_issues == -1
		msg = "List of Blocker Issues for Sonarqube Project could not be accessed."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
		error = "Failed while fetching blocker issues from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		count(blocker_issues) > 0
		some idx
		blocker_issues[idx].message in exception_list
		title := sprintf("Sonarqube Scan: %v", [blocker_issues[idx].message])
		msg = blocker_issues[idx].message
		sugg = "Kindly refer to the suggested resolutions by Sonarqube. For more details about the error, please refer to the detailed scan results."
		error = ""
		exception_cause := blocker_issues[idx].message
		alertStatus := "exception"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(blocker_issues) > 0
		some idx
		not blocker_issues[idx].message in exception_list
		title := sprintf("Sonarqube Scan: %v", [blocker_issues[idx].message])
		msg = blocker_issues[idx].message
		sugg = "Kindly refer to the suggested resolutions by Sonarqube. For more details about the error, please refer to the detailed scan results."
		error = ""
		exception_cause := blocker_issues[idx].message
		alertStatus := "active"
	}`,

	330: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default count_critical_issues = -1

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	critical_issues = response.body.criticalIssues
	count_critical_issues = count(critical_issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_critical_issues == -1
		msg = "List of Critical Issues for Sonarqube Project could not be accessed."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
		error = "Failed while fetching critical issues from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		count_critical_issues > 0
		some idx
		critical_issues[idx].message in exception_list
		title := sprintf("Sonarqube Scan: %v", [critical_issues[idx].message])
		msg = critical_issues[idx].message
		sugg = "Kindly refer to the suggested resolutions by Sonarqube. For more details about the error, please refer to the detailed scan results."
		error = ""
		exception_cause := critical_issues[idx].message
		alertStatus := "exception"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count_critical_issues > 0
		some idx
		not critical_issues[idx].message in exception_list
		title := sprintf("Sonarqube Scan: %v", [critical_issues[idx].message])
		msg = critical_issues[idx].message
		sugg = "Kindly refer to the suggested resolutions by Sonarqube. For more details about the error, please refer to the detailed scan results."
		error = ""
		exception_cause := critical_issues[idx].message
		alertStatus := "active"
	}`,

	331: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default facetvalues := []

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	facetvalues := response.body.facets[_].values

	critical_count := [facetvalues[i].count | facetvalues[i].val == "CRITICAL"]
	blocker_count := [facetvalues[i].count | facetvalues[i].val == "BLOCKER"]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) == 0
		msg = "No facet values found for severities."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
		error = "Failed while fetching severity count from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		critical_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		critical_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		blocker_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		blocker_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}`,

	332: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default facetvalues := []

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	facetvalues := response.body.facets[_].values

	major_count := [facetvalues[i].count | facetvalues[i].val == "MAJOR"]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) == 0
		msg = "No facet values found for severities."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
		error = "Failed while fetching severity count from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		major_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Major issues found during SAST scan for repository %v/%v and branch %v. \nMajor Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, major_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		major_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Major issues found during SAST scan for repository %v/%v and branch %v. \nMajor Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, major_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}`,

	333: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default facetvalues := []
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	facetvalues := response.body.facets[_].values

	info_count := [facetvalues[i].count | facetvalues[i].val == "INFO"]
	minor_count := [facetvalues[i].count | facetvalues[i].val == "MINOR"]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) == 0
		msg = "No facet values found for severities."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
		error = "Failed while fetching severity count from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		minor_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		minor_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		info_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		info_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}`,

	334: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default count_critical_issues = -1
	default count_issues = -1
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_codacy.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_codacy.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codacyscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codacyscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = response.body.codacyAnalysis
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of Issues for Codacy Project could not be accessed."
		sugg = "Kindly check if the Codacy token is configured and has permissions to read issues of the project."
		error = "Failed while fetching issues from Codacy."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Error"
		not policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Error"
		policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "exception"
	}`,

	335: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default count_issues = -1
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_codacy.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_codacy.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codacyscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codacyscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = response.body.codacyAnalysis
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of Issues for Codacy Project could not be accessed."
		sugg = "Kindly check if the Codacy token is configured and has permissions to read issues of the project."
		error = "Failed while fetching issues from Codacy."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Warning"
		not policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Warning"
		policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "exception"
	}`,

	336: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default count_issues = -1
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_codacy.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_codacy.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codacyscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codacyscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = response.body.codacyAnalysis
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of Issues for Codacy Project could not be accessed."
		sugg = "Kindly check if the Codacy token is configured and has permissions to read issues of the project."
		error = "Failed while fetching issues from Codacy."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Info"
		not policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Info"
		policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "exception"
	}`,

	337: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default issues = []
	default count_issues = -1

	image_sha = replace(input.metadata.image_sha, ":", "-")

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"] )


	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = [response.body.zapAlerts[i] | response.body.zapAlerts[i].risk == "High"]
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of High Severity Issues for OWASP ZAP Scan could not be accessed."
		sugg = "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint."
		error = "Failed while fetching issues from OWASP ZAP."
		alertStatus := "error"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		exception_cause := issues[idx].name
		alertStatus := "exception"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		not issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		alertStatus := "active"
	}`,

	338: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default issues = []
	default count_issues = -1

	image_sha = replace(input.metadata.image_sha, ":", "-")

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"] )


	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = [response.body.zapAlerts[i] | response.body.zapAlerts[i].risk == "Medium"]
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of High Severity Issues for OWASP ZAP Scan could not be accessed."
		sugg = "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint."
		error = "Failed while fetching issues from OWASP ZAP."
		alertStatus := "error"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		exception_cause := issues[idx].name
		alertStatus := "exception"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		not issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		alertStatus := "active"
	}`,

	339: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default issues = []
	default count_issues = -1

	image_sha = replace(input.metadata.image_sha, ":", "-")


	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"] )


	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = [response.body.zapAlerts[i] | response.body.zapAlerts[i].risk == "Low"]
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of High Severity Issues for OWASP ZAP Scan could not be accessed."
		sugg = "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint."
		error = "Failed while fetching issues from OWASP ZAP."
		alertStatus := "error"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		exception_cause := issues[idx].name
		alertStatus := "exception"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		not issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		alertStatus := "active"
	}`,

	340: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default issues = []
	default count_issues = -1

	image_sha = replace(input.metadata.image_sha, ":", "-")


	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "_", input.metadata.deploymentId, "_zapScan.json&scanOperation=zapDastScan"] )


	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = [response.body.zapAlerts[i] | response.body.zapAlerts[i].risk == "Informational"]
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of High Severity Issues for OWASP ZAP Scan could not be accessed."
		sugg = "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint."
		error = "Failed while fetching issues from OWASP ZAP."
		alertStatus := "error"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		exception_cause := issues[idx].name
		alertStatus := "exception"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count_issues > 0
		some idx
		not issues[idx].name in exception_list
		title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
		msg = issues[idx].description
		sugg = issues[idx].solution
		error = ""
		alertStatus := "active"
	}`,

	341: `
	package opsmx
	severities = ["LOW"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity
		msg:= sprintf("%v Criticality Vulnerability : %v found in plugin: %v", [inputSeverity, vuln_id, input.metadata.plugin_name])
	}`,

	342: `
	package opsmx
	severities = ["CRITICAL"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity
		msg:= sprintf("%v Criticality Vulnerability : %v found in plugin: %v", [inputSeverity, vuln_id, input.metadata.plugin_name])
	}
	`,

	343: `
	package opsmx
	severities = ["MODERATE","UNDEFINED","MEDIUM","UNKNOWN"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity 
		msg:= sprintf("%v Criticality Vulnerability : %v found in plugin: %v", [inputSeverity, vuln_id, input.metadata.plugin_name])
	} `,

	344: `
	package opsmx
	severities = ["HIGH"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity
		msg:= sprintf("%v Criticality Vulnerability : %v found in plugin: %v", [inputSeverity, vuln_id, input.metadata.plugin_name])
	}
	`,

	345: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
        default remediation := ""

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default findings_count = 0

	cloud_account_name := input.metadata.cloudAccountName
	results := input.metadata.cspmFindings

	flagged_items = results.flagged_items
	rule_description := results.description
	rule_name := results.name
	rule_rationale = results.rationale
	references = concat(" \n", results.references)
        remediation = results.remediation

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
			flagged_items > 0
			not rule_name in exception_list
			some i
			violated_resource := results.affectedResources[i].name
			service_type := results.service

			title := sprintf("Rule: %v violated for %v resource %v", [rule_name, service_type, violated_resource])
			msg := sprintf("Rule: %v violated for %v resource %v. \nRule Description: %v. \n Detailed Description: %v.", [rule_name, service_type, violated_resource, rule_description, rule_rationale])
			error := ""
			sugg := sprintf("%v \n %v", [remediation, references])
			alertStatus := "active"
	}


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
			flagged_items > 0
			rule_name in exception_list
			some i
			violated_resource := results.affectedResources[i].name
			service_type := results.service

			title := sprintf("Rule: %v violated for %v resource %v", [rule_name, service_type, violated_resource])
			msg := sprintf("Rule: %v violated for %v resource %v. \nRule Description: %v. \n Detailed Description: %v.", [rule_name, service_type, violated_resource, rule_description, rule_rationale])
			error := ""
			sugg := sprintf("%v \n %v", [remediation, references])
			exception_cause := rule_name
			alertStatus := "exception"
	}`,

	383: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	file_name = concat("", [input.metadata.mobileBuild, "_", input.metadata.image_sha, "_virustotal-mobapp-scan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=virusTotalMobAppScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=virusTotalMobAppScan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	deny [{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some rule in response.body.data.attributes.results
		rule.category == "malicious"
		engine = rule.engine_name
		engine_version = rule.engine_version
		result = rule.result

		exception_str=concat(":", [engine, result])
		not exception_str in exception_list
	
		title := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with malicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		msg := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with malicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny [{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some rule in response.body.data.attributes.results
		rule.category == "malicious"
		engine = rule.engine_name
		engine_version = rule.engine_version
		result = rule.result

		exception_str=concat(":", [engine, result])
		exception_str in exception_list

		title := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with malicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		msg := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with malicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		sugg := ""
		error := ""
		exception_cause := exception_str
		alertStatus := "exception"
	}
	`,

	384: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	file_name = concat("", [input.metadata.mobileBuild, "_", input.metadata.image_sha, "_virustotal-mobapp-scan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=virusTotalMobAppScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=virusTotalMobAppScan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	deny [{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some rule in response.body.data.attributes.results
		rule.category == "suspicious"
		engine = rule.engine_name
		engine_version = rule.engine_version
		result = rule.result

		exception_str=concat(":", [engine, result])
		not exception_str in exception_list
	
		title := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		msg := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny [{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some rule in response.body.data.attributes.results
		rule.category == "suspicious"
		engine = rule.engine_name
		engine_version = rule.engine_version
		result = rule.result

		exception_str=concat(":", [engine, result])
		exception_str in exception_list

		title := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		msg := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		sugg := ""
		error := ""
		exception_cause := exception_str
		alertStatus := "exception"
	}
	`,

	385: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"]) 

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	low_severity_certificate_findings := [response.body.certificate_analysis.certificate_findings[i] | response.body.certificate_analysis.certificate_findings[i][0] == "Low"]
	low_severity_certificate_issue_count := count(low_severity_certificate_findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		low_severity_certificate_issue_count > 0
		some idx in low_severity_certificate_findings
		not idx[2] in exception_list
	
		title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
		msg := idx[1]
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		low_severity_certificate_issue_count > 0
		some idx in low_severity_certificate_findings
		idx[2] in exception_list
	
		title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
		msg := idx[1]
		sugg := ""
		error := ""
		exception_cause := idx[2]
		alertStatus := "exception"
	}`,

	386: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"]) 

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	medium_severity_certificate_findings := [response.body.certificate_analysis.certificate_findings[i] | response.body.certificate_analysis.certificate_findings[i][0] == "Medium"]
	medium_severity_certificate_issue_count := count(medium_severity_certificate_findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		medium_severity_certificate_issue_count > 0
		some idx in medium_severity_certificate_findings
		not idx[2] in exception_list
	
		title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
		msg := idx[1]
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		medium_severity_certificate_issue_count > 0
		some idx in medium_severity_certificate_findings
		idx[2] in exception_list
	
		title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
		msg := idx[1]
		sugg := ""
		error := ""
		exception_cause := idx[2]
		alertStatus := "exception"
	}`,

	387: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"]) 

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	high_severity_certificate_findings := [response.body.certificate_analysis.certificate_findings[i] | response.body.certificate_analysis.certificate_findings[i][0] == "High"]
	high_severity_certificate_issue_count := count(high_severity_certificate_findings)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		high_severity_certificate_issue_count > 0
		some idx in high_severity_certificate_findings
		not idx[2] in exception_list
	
		title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
		msg := idx[1]
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		high_severity_certificate_issue_count > 0
		some idx in high_severity_certificate_findings
		idx[2] in exception_list
	
		title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
		msg := idx[1]
		sugg := ""
		error := ""
		exception_cause := idx[2]
		alertStatus := "exception"
	}`,

	388: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		permission := response.body.permissions[key]
		permission.status == "Low"
		not key in exception_list
		info := permission.info
		desc := permission.description
		title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
		msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		permission := response.body.permissions[key]
		permission.status == "Low"
		key in exception_list
		info := permission.info
		desc := permission.description
		title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
		msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}`,

	389: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		permission := response.body.permissions[key]
		permission.status == "Medium"
		not key in exception_list
		info := permission.info
		desc := permission.description
		title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
		msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		permission := response.body.permissions[key]
		permission.status == "Medium"
		key in exception_list
		info := permission.info
		desc := permission.description
		title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
		msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}`,

	390: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		permission := response.body.permissions[key]
		permission.status == "High"
		not key in exception_list
		info := permission.info
		desc := permission.description
		title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
		msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		permission := response.body.permissions[key]
		permission.status == "High"
		key in exception_list
		info := permission.info
		desc := permission.description
		title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
		msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}`,

	391: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default low_severity_manifest_issue_count := 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	low_severity_manifest_findings = [response.body.manifest_analysis.manifest_findings[idx] | response.body.manifest_analysis.manifest_findings[idx].severity == "Low"]
	low_severity_manifest_issue_count = count(low_severity_manifest_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in low_severity_manifest_findings
		rule := finding.rule
		rule_title := finding.title
		description := finding.description
		components := concat(",", finding.component)

		not rule in exception_list
		
		title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": rule, "alertStatus": alertStatus}]{
		some finding in low_severity_manifest_findings
		rule := finding.rule
		rule_title := finding.title
		description := finding.description
		components := concat(",", finding.component)

		rule in exception_list
		
		title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	392: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default medium_severity_manifest_issue_count := 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	medium_severity_manifest_findings = [response.body.manifest_analysis.manifest_findings[idx] | response.body.manifest_analysis.manifest_findings[idx].severity == "Medium"]
	medium_severity_manifest_issue_count = count(medium_severity_manifest_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in medium_severity_manifest_findings
		rule := finding.rule
		rule_title := finding.title
		description := finding.description
		components := concat(",", finding.component)

		not rule in exception_list
		
		title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": rule, "alertStatus": alertStatus}]{
		some finding in medium_severity_manifest_findings
		rule := finding.rule
		rule_title := finding.title
		description := finding.description
		components := concat(",", finding.component)

		rule in exception_list
		
		title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	393: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default high_severity_manifest_issue_count := 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	high_severity_manifest_findings = [response.body.manifest_analysis.manifest_findings[idx] | response.body.manifest_analysis.manifest_findings[idx].severity == "High"]
	high_severity_manifest_issue_count = count(high_severity_manifest_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in high_severity_manifest_findings
		rule := finding.rule
		rule_title := finding.title
		description := finding.description
		components := concat(",", finding.component)

		not rule in exception_list
		
		title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": rule, "alertStatus": alertStatus}]{
		some finding in high_severity_manifest_findings
		rule := finding.rule
		rule_title := finding.title
		description := finding.description
		components := concat(",", finding.component)

		rule in exception_list
		
		title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	394: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default low_severity_network_issue_count := 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	low_severity_network_findings = [response.body.network_security.network_findings[idx] | response.body.network_security.network_findings[idx].severity == "Low"]
	low_severity_network_issue_count = count(low_severity_network_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in low_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		not description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": description, "alertStatus": alertStatus}]{
		some finding in low_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	395: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default medium_severity_network_issue_count := 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	medium_severity_network_findings = [response.body.network_security.network_findings[idx] | response.body.network_security.network_findings[idx].severity == "Medium"]
	medium_severity_network_issue_count = count(medium_severity_network_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in medium_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		not description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": description, "alertStatus": alertStatus}]{
		some finding in medium_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	396: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default high_severity_network_issue_count := 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	high_severity_network_findings = [response.body.network_security.network_findings[idx] | response.body.network_security.network_findings[idx].severity == "High"]
	high_severity_network_issue_count = count(high_severity_network_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in high_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		not description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": description, "alertStatus": alertStatus}]{
		some finding in high_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	397: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.binary_analysis.findings[key]
		finding.severity == "Low"

		not key in exception_list

		desc := finding.detailed_desc
		title := key
		msg := sprintf("Binary Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v", [artifact_name, desc, finding.cvss, finding.cwe, finding.masvs])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.binary_analysis.findings[key]
		finding.severity == "Low"

		key in exception_list

		desc := finding.detailed_desc
		title := key
		msg := sprintf("Binary Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v", [artifact_name, desc, finding.cvss, finding.cwe, finding.masvs])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}`,

	398: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.binary_analysis.findings[key]
		finding.severity == "Medium"

		not key in exception_list

		desc := finding.detailed_desc
		title := key
		msg := sprintf("Binary Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v", [artifact_name, desc, finding.cvss, finding.cwe, finding.masvs])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.binary_analysis.findings[key]
		finding.severity == "Medium"

		key in exception_list

		desc := finding.detailed_desc
		title := key
		msg := sprintf("Binary Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v", [artifact_name, desc, finding.cvss, finding.cwe, finding.masvs])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}`,

	399: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.binary_analysis.findings[key]
		finding.severity == "High"

		not key in exception_list

		desc := finding.detailed_desc
		title := key
		msg := sprintf("Binary Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v", [artifact_name, desc, finding.cvss, finding.cwe, finding.masvs])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.binary_analysis.findings[key]
		finding.severity == "High"

		key in exception_list

		desc := finding.detailed_desc
		title := key
		msg := sprintf("Binary Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v", [artifact_name, desc, finding.cvss, finding.cwe, finding.masvs])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}`,

	400: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "Low"

		not key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "Low"

		key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "active"
	}`,

	401: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "Medium"

		not key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "Medium"

		key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "active"
	}`,

	402: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "High"

		not key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "High"

		key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "active"
	}`,

	403: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {	
		some key
		finding := response.body.code_analysis.findings[key]
		finding.metadata.severity == "Low"

		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Code Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description    
		msg := sprintf("Code Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v \n Impacted Files: %v", [artifact_name, desc, finding.metadata.cvss, finding.metadata.cwe, finding.metadata.masvs, files])
		sugg := finding.metadata.ref
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {	
		some key
		finding := response.body.code_analysis.findings[key]
		finding.metadata.severity == "Low"

		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Code Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description    
		msg := sprintf("Code Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v \n Impacted Files: %v", [artifact_name, desc, finding.metadata.cvss, finding.metadata.cwe, finding.metadata.masvs, files])
		sugg := finding.metadata.ref
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}


	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat("\n", keys)  # Join the keys with newline characters
	}`,

	404: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {	
		some key
		finding := response.body.code_analysis.findings[key]
		finding.metadata.severity == "Medium"

		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Code Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description    
		msg := sprintf("Code Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v \n Impacted Files: %v", [artifact_name, desc, finding.metadata.cvss, finding.metadata.cwe, finding.metadata.masvs, files])
		sugg := finding.metadata.ref
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {	
		some key
		finding := response.body.code_analysis.findings[key]
		finding.metadata.severity == "Medium"

		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Code Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description    
		msg := sprintf("Code Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v \n Impacted Files: %v", [artifact_name, desc, finding.metadata.cvss, finding.metadata.cwe, finding.metadata.masvs, files])
		sugg := finding.metadata.ref
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}


	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat("\n", keys)  # Join the keys with newline characters
	}`,

	405: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {	
		some key
		finding := response.body.code_analysis.findings[key]
		finding.metadata.severity == "High"

		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Code Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description    
		msg := sprintf("Code Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v \n Impacted Files: %v", [artifact_name, desc, finding.metadata.cvss, finding.metadata.cwe, finding.metadata.masvs, files])
		sugg := finding.metadata.ref
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {	
		some key
		finding := response.body.code_analysis.findings[key]
		finding.metadata.severity == "High"

		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Code Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description    
		msg := sprintf("Code Analysis Failure in artifact: %v \n Description: %v \n CVSS: %v \n CWE: %v \n MASVS: %v \n Impacted Files: %v", [artifact_name, desc, finding.metadata.cvss, finding.metadata.cwe, finding.metadata.masvs, files])
		sugg := finding.metadata.ref
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}


	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat("\n", keys)  # Join the keys with newline characters
	}`,

	406: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	low_severity_findings := response.body.appsec.Low

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {	
		some finding in low_severity_findings

		not finding.title in exception_list

		title := finding.title
		msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": title, "alertStatus": alertStatus}] {
		some finding in low_severity_findings

		finding.title in exception_list
		
		title := finding.title
		msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	407: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	medium_severity_findings := response.body.appsec.Medium

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {	
		some finding in medium_severity_findings

		not finding.title in exception_list

		title := finding.title
		msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": title, "alertStatus": alertStatus}] {
		some finding in medium_severity_findings

		finding.title in exception_list
		
		title := finding.title
		msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	408: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	artifact_name := response.body.artifactName

	high_severity_findings := response.body.appsec.High

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {	
		some finding in high_severity_findings

		not finding.title in exception_list

		title := finding.title
		msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": title, "alertStatus": alertStatus}] {
		some finding in high_severity_findings

		finding.title in exception_list
		
		title := finding.title
		msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}`,

	409: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {
		some key
		finding := response.body.android_api[key]

		finding.metadata.severity == "Low"
		
		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Android API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("Android API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {
		some key
		finding := response.body.android_api[key]

		finding.metadata.severity == "Low"
		
		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Android API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("Android API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}

	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat(" \n", keys)  # Join the keys with newline characters
	}`,

	410: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {
		some key
		finding := response.body.android_api[key]

		finding.metadata.severity == "Medium"
		
		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Android API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("Android API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {
		some key
		finding := response.body.android_api[key]

		finding.metadata.severity == "Medium"
		
		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Android API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("Android API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}

	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat(" \n", keys)  # Join the keys with newline characters
	}`,

	411: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {
		some key
		finding := response.body.android_api[key]

		finding.metadata.severity == "High"
		
		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Android API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("Android API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {
		some key
		finding := response.body.android_api[key]

		finding.metadata.severity == "High"
		
		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("Android API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("Android API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}

	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat(" \n", keys)  # Join the keys with newline characters
	}`,

	412: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {
		some key
		finding := response.body.ios_api[key]

		finding.metadata.severity == "Low"
		
		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {
		some key
		finding := response.body.ios_api[key]

		finding.metadata.severity == "Low"
		
		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}

	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat(" \n", keys)  # Join the keys with newline characters
	}`,

	413: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {
		some key
		finding := response.body.ios_api[key]

		finding.metadata.severity == "Medium"
		
		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {
		some key
		finding := response.body.ios_api[key]

		finding.metadata.severity == "Medium"
		
		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}

	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat(" \n", keys)  # Join the keys with newline characters
	}`,

	414: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}] {
		some key
		finding := response.body.ios_api[key]

		finding.metadata.severity == "High"
		
		not key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}] {
		some key
		finding := response.body.ios_api[key]

		finding.metadata.severity == "High"
		
		key in exception_list

		files := concat_keys(finding.files)
		title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		desc := finding.metadata.description
		msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "exception"
	}

	concat_keys(files) = result {
		keys := {k | files[k]}   # Extract the keys from the input object
		result := concat(" \n", keys)  # Join the keys with newline characters
	}`,

	415: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	terraform_repo_url_arr = split(input.metadata.ssd_secret.tfsec.url, "/")
	terraform_repo_name = split(terraform_repo_url_arr[count(terraform_repo_url_arr)-1], ".")[0]

	deployment_id = input.metadata.deploymentId

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [terraform_repo_name, "_", deployment_id, "_", image_sha, "_tfsecscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=tfsecscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=tfsecscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	issues := [response.body.results[idx] |response.body.results[idx].severity == "Low"]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some issue in issues
		title = issue.rule_description

		not issue.long_id in exception_list

		msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
		sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
		error = ""
		alertStatus = "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some issue in issues
		title = issue.rule_description

		issue.long_id in exception_list

		msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
		sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
		error = ""
		exception_cause = issue.long_id
		alertStatus = "exception"
	}`,

	416: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	terraform_repo_url_arr = split(input.metadata.ssd_secret.tfsec.url, "/")
	terraform_repo_name = split(terraform_repo_url_arr[count(terraform_repo_url_arr)-1], ".")[0]

	deployment_id = input.metadata.deploymentId

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [terraform_repo_name, "_", deployment_id, "_", image_sha, "_tfsecscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=tfsecscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=tfsecscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	issues := [response.body.results[idx] |response.body.results[idx].severity == "Medium"]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some issue in issues
		title = issue.rule_description

		not issue.long_id in exception_list

		msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
		sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
		error = ""
		alertStatus = "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some issue in issues
		title = issue.rule_description

		issue.long_id in exception_list

		msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
		sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
		error = ""
		exception_cause = issue.long_id
		alertStatus = "exception"
	}`,

	417: `
	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	terraform_repo_url_arr = split(input.metadata.ssd_secret.tfsec.url, "/")
	terraform_repo_name = split(terraform_repo_url_arr[count(terraform_repo_url_arr)-1], ".")[0]

	deployment_id = input.metadata.deploymentId

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [terraform_repo_name, "_", deployment_id, "_", image_sha, "_tfsecscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=tfsecscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=tfsecscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	issues := [response.body.results[idx] |response.body.results[idx].severity == "High"]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some issue in issues
		title = issue.rule_description

		not issue.long_id in exception_list

		msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
		sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
		error = ""
		alertStatus = "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some issue in issues
		title = issue.rule_description

		issue.long_id in exception_list

		msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
		sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
		error = ""
		exception_cause = issue.long_id
		alertStatus = "exception"
	}`,
}

var policyDefinition = []string{
	`
	{
		 "policyId":"1",
		 "orgId":"1",
		 "policyName":"Repository Access Control Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Code Repository should not be publicly visible or modifiable.",
		 "scheduled_policy":false,
		 "scriptId":"1",
		 "variables":"",
		 "conditionName":"Repository Access Control Policy"
	}
	`,
	`
	{
		 "policyId":"2",
		 "orgId":"1",
		 "policyName":"Minimum Reviewers Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Pushed code should be reviewed by a minimum number of users:2 as defined in the policy.",
		 "scheduled_policy":false,
		 "scriptId":"2",
		 "variables":"",
		 "conditionName":"Minimum Reviewers Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"3",
		 "orgId":"1",
		 "policyName":"Branch Protection Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Repositories should have branch protection enabled requiring all code changes to be reviewed. This means disabling Push events and requiring Pull/Merge Requests to have code reviews.",
		 "scheduled_policy":false,
		 "scriptId":"3",
		 "variables":"",
		 "conditionName":"Branch Protection Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"4",
		 "orgId":"1",
		 "policyName":"Branch Deletion Prevention Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"While the default branch can’t be deleted directly even if the setting is on, in general, it is best practice to prevent branches from being deleted by anyone with write access.",
		 "scheduled_policy":false,
		 "scriptId":"4",
		 "variables":"",
		 "conditionName":"Branch Deletion Prevention Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"5",
		 "orgId":"1",
		 "policyName":"Commit Signing Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Commit signing should be mandatory. Signing commits is needed because it is pretty easy to add anyone as the author of a commit. Git allows a committer to change the author of a commit easily. In the case of a signed commit, any change to the author will make the commit appear unsigned.",
		 "scheduled_policy":false,
		 "scriptId":"5",
		 "variables":"",
		 "conditionName":"Commit Signing Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"6",
		 "orgId":"1",
		 "policyName":"Repository 2FA Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Repositories should be protected based on 2FA authentication",
		 "scheduled_policy":false,
		 "scriptId":"6",
		 "variables":"",
		 "conditionName":"Repository 2FA Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"7",
		 "orgId":"1",
		 "policyName":"Low Vulnerability Prevention Policy",
		 "category":"Vulnerability Analysis",
		 "stage":"artifact",
		 "description":"Low Severity Vulnerability should not be found in the artifact",
		 "scheduled_policy":true,
		 "scriptId":"7",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"8",
		 "orgId":"1",
		 "policyName":"Critical Vulnerability Prevention Policy",
		 "category":"Vulnerability Analysis",
		 "stage":"artifact",
		 "description":"Critical Severity Vulnerabilities should not be found in the artifact",
		 "scheduled_policy":true,
		 "scriptId":"8",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"9",
		 "orgId":"1",
		 "policyName":"Medium Vulnerability Prevention Policy",
		 "category":"Vulnerability Analysis",
		 "stage":"artifact",
		 "description":"Medium Severity Vulnerabilities should not be found in the artifact",
		 "scheduled_policy":true,
		 "scriptId":"9",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"10",
		 "orgId":"1",
		 "policyName":"Build Workflow Permissions over Organization Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Build Workflow should have minimum permissions over organization configuration.",
		 "scheduled_policy":false,
		 "scriptId":"10",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"11",
		 "orgId":"1",
		 "policyName":"Build Workflow Permissions over Repository Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Build Workflow should have minimum permissions over repository configuration",
		 "scheduled_policy":false,
		 "scriptId":"11",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"12",
		 "orgId":"1",
		 "policyName":"Identical Build and Cloud Artifact Policy",
		 "category":"Artifact Integrity",
		 "stage":"build",
		 "description":"Build signature in Build Environment and Cloud Environment during Deployment should be identical to confirm integrity of the artifact.",
		 "scheduled_policy":false,
		 "scriptId":"12",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"13",
		 "orgId":"1",
		 "policyName":"Open SSF Branch Protection Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This evaluates if the project main and release branches are safeguarded with GitHub branch protection settings, enforcing review and status check requirements before merging and preventing history changes.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Branch Protection Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"14",
		 "orgId":"1",
		 "policyName":"Open SSF CI Tests Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This assesses if the project enforces running tests before merging pull requests, currently applicable only to GitHub-hosted repositories, excluding other source hosting platforms.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF CI Tests Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"15",
		 "orgId":"1",
		 "policyName":"Open SSF CII-Best Practices Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This evaluates if the project has achieved an OpenSSF Best Practices Badge to indicate adherence to security-focused best practices, using the Git repo URL and OpenSSF Badge API",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF CII-Best Practices Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"16",
		 "orgId":"1",
		 "policyName":"Open SSF Code Review Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check determines whether the project requires human code review before pull requests are merged.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Code Review Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"17",
		 "orgId":"1",
		 "policyName":"Open SSF Contributors Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check assesses if the project has recent contributors from various organizations, applicable only to GitHub-hosted repositories, without support for other source hosting platforms",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Contributors Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"18",
		 "orgId":"1",
		 "policyName":"Open SSF Dangerous Workflow Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This identifies risky code patterns in the project GitHub Action workflows, such as untrusted code checkouts, logging sensitive information, or using potentially unsafe inputs in scripts",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Dangerous Workflow Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"19",
		 "orgId":"1",
		 "policyName":"Open SSF Dependency Update Tool Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This evaluates if the project utilizes a dependency update tool like Dependabot, Renovate bot, Sonatype Lift, or PyUp to automate updating outdated dependencies and enhance security",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Dependency Update Tool Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"20",
		 "orgId":"1",
		 "policyName":"Open SSF Fuzzing Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This assesses if the project employs fuzzing, considering various criteria including repository inclusion, fuzzing tool presence, language-specific functions, and integration files.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Fuzzing Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"21",
		 "orgId":"1",
		 "policyName":"Open SSF License Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This examines if the project has a published license by using hosting APIs or searching for a license file using standard naming conventions",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF License Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"22",
		 "orgId":"1",
		 "policyName":"Open SSF Maintained Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check evaluates project maintenance status based on commit frequency, issue activity, and archival status",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Maintained Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"23",
		 "orgId":"1",
		 "policyName":"Open SSF Pinned Dependencies Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This verifies if a project locks its dependencies to specific versions by their hashes, applicable only to GitHub repositories.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Pinned Dependencies Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"24",
		 "orgId":"1",
		 "policyName":"Open SSF Packaging Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This assesses if the project is released as a package.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Packaging Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"25",
		 "orgId":"1",
		 "policyName":"Open SSF SAST Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check assesses if a GitHub-hosted project employs Static Application Security Testing.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF SAST Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"26",
		 "orgId":"1",
		 "policyName":"Open SSF Security Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check tries to determine if the project has published a security policy. It works by looking for a file named SECURITY.md in a few well-known directories.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Security Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"27",
		 "orgId":"1",
		 "policyName":"Open SSF Signed Releases Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This determines if the project cryptographically signs release artefacts.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Signed Releases Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"28",
		 "orgId":"1",
		 "policyName":"Open SSF Token Permissions Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This Determines Whether the project automated workflow tokens follow the principle of least privilege.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Token Permissions Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"29",
		 "orgId":"1",
		 "policyName":"Open SSF Vulnerabilities Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"The Project Has Open, Unfixed Vulnerabilities in its Own codebase.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Vulnerabilities Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"30",
		 "orgId":"1",
		 "policyName":"Open SSF Webhooks Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check determines whether the webhook defined in the repository has a token configured to authenticate the origins of requests.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Webhooks Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"31",
		 "orgId":"1",
		 "policyName":"Open SSF Binary Artifacts Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"This check determines whether the project has generated executable artifacts in the source repository.",
		 "scheduled_policy":false,
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Binary Artifacts Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"32",
		 "orgId":"1",
		 "policyName":"Restricted Repository Access: Internal Authorization Only",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"This policy limits repository access to internal personnel only, ensuring secure and controlled information management.",
		 "scheduled_policy":false,
		 "scriptId":"32",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"33",
		 "orgId":"1",
		 "policyName":"Bot User should not be a Repository Admin",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot Users should not be a Repository Administrator. Bot user is identified using some well-known patterns.",
		 "scheduled_policy":false,
		 "scriptId":"33",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"34",
		 "orgId":"1",
		 "policyName":"Bot User should not be a Org Owner",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot User should not be a Org Owner. Bot user is identified using some well-known patterns.",
		 "scheduled_policy":false,
		 "scriptId":"34",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"35",
		 "orgId":"1",
		 "policyName":"Build Webhook Authenticated Protection Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Webhooks used in workflows should be protected/authenticated.",
		 "scheduled_policy":false,
		 "scriptId":"35",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"36",
		 "orgId":"1",
		 "policyName":"Build Webhook SSL/TLS Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Webhooks should use SSL/TLS.",
		 "scheduled_policy":false,
		 "scriptId":"36",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"37",
		 "orgId":"1",
		 "policyName":"Build Server Origin Check",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Build Server Origin Check is a policy that ensures artifacts originate from approved build servers for secure deployments.",
		 "scheduled_policy":false,
		 "scriptId":"37",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"38",
		 "orgId":"1",
		 "policyName":"Pre-Deployment Checksum Verify",
		 "category":"Artifact Integrity",
		 "stage":"artifact",
		 "description":"Pre-Deployment Checksum Verify is a security policy that validates artifact integrity by comparing build-time checksums with Docker checksums, ensuring trusted and unaltered artifacts are used for deployment.",
		 "scheduled_policy":false,
		 "scriptId":"38",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"39",
		 "orgId":"1",
		 "policyName":"Cloud Artifact should match the build artifact by hash",
		 "category":"Artifact Integrity",
		 "stage":"deploy",
		 "description":"An image hash not matched to a build artifact may indicate a compromise of the cloud account. An unauthorized application may be running in your organizations cloud.",
		 "scheduled_policy":false,
		 "scriptId":"39",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"40",
		 "orgId":"1",
		 "policyName":"Repository License Inclusion Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Repositories should contain licence files",
		 "scheduled_policy":false,
		 "scriptId":"40",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"41",
		 "orgId":"1",
		 "policyName":"Approved Artifact Repo Origin",
		 "category":"Artifact Integrity",
		 "stage":"artifact",
		 "description":"Approved Artifact Repo Origin policy validates artifacts from authorized repositories, ensuring secure deployments.",
		 "scheduled_policy":false,
		 "scriptId":"41",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"42",
		 "orgId":"1",
		 "policyName":"Open SSF Aggregate Score Policy",
		 "category":"OpenSSF Scorecard",
		 "stage":"source",
		 "description":"The project might have known security vulnerabilities that have not been adequately  addressed",
		 "scheduled_policy":false,
		 "scriptId":"42",
		 "variables":"",
		 "conditionName":"Open SSF Aggregate Score Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"43",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating D Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade D rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "scriptId":"43",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating D Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"44",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating C Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade C rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "scriptId":"44",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating C Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"45",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating B Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade B rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "scriptId":"45",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating B Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"46",
		 "orgId":"1",
		 "policyName":"Block Container Without Limits",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Requires containers to have memory and CPU limits set and constrains limits to be within the specified maximum values.",
		 "scheduled_policy":false,
		 "scriptId":"46",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"47",
		 "orgId":"1",
		 "policyName":"Block Container Without Request Limit",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Requires containers to have memory and CPU requests set and constrains requests to be within the specified maximum values.",
		 "scheduled_policy":false,
		 "scriptId":"47",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"48",
		 "orgId":"1",
		 "policyName":"SEMGREP High Severity Findings Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of high-severity findings in SEMGREP analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "scriptId":"48",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"49",
		 "orgId":"1",
		 "policyName":"SEMGREP Medium Severity Findings Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of medium-severity findings in SEMGREP analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "scriptId":"49",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"50",
		 "orgId":"1",
		 "policyName":"Block Undefined Container Ratios",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Sets a maximum ratio for container resource limits to requests.",
		 "scheduled_policy":false,
		 "scriptId":"50",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"51",
		 "orgId":"1",
		 "policyName":"SAST Integration Validation Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Ensures atleast one SAST tool is configured for Source Repo.",
		 "scheduled_policy":false,
		 "scriptId":"51",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"52",
		 "orgId":"1",
		 "policyName":"SEMGREP Low Severity Findings Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of low-severity findings in SEMGREP analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "scriptId":"52",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"53",
		 "orgId":"1",
		 "policyName":"Pod Security Allow Privilege Escalation",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls restricting escalation to root privileges.",
		 "scheduled_policy":false,
		 "scriptId":"53",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"54",
		 "orgId":"1",
		 "policyName":"Pod Security App Armor",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Configures an allow-list of AppArmor profiles for use by containers.",
		 "scheduled_policy":false,
		 "scriptId":"54",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"55",
		 "orgId":"1",
		 "policyName":"Pod Security Capabilities",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls Linux capabilities on containers.",
		 "scheduled_policy":false,
		 "scriptId":"55",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"56",
		 "orgId":"1",
		 "policyName":"Pod Security Flex Volumes",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls the allowlist of FlexVolume drivers.",
		 "scheduled_policy":false,
		 "scriptId":"56",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"57",
		 "orgId":"1",
		 "policyName":"Pod Security Forbidden Sysctl",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls the sysctl profile used by containers.",
		 "scheduled_policy":false,
		 "scriptId":"57",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"58",
		 "orgId":"1",
		 "policyName":"Pod Security FS Group",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls allocating an FSGroup that owns the Pods volumes.",
		 "scheduled_policy":false,
		 "scriptId":"58",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"59",
		 "orgId":"1",
		 "policyName":"Pod Security Host Filesystem",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls usage of the host filesystem.",
		 "scheduled_policy":false,
		 "scriptId":"59",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"60",
		 "orgId":"1",
		 "policyName":"Pod Security Host Namespace",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Disallows sharing of host PID and IPC namespaces by pod containers.",
		 "scheduled_policy":false,
		 "scriptId":"60",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"61",
		 "orgId":"1",
		 "policyName":"Pod Security Host Network",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls usage of host network namespace by pod containers. Specific ports must be specified.",
		 "scheduled_policy":false,
		 "scriptId":"61",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"62",
		 "orgId":"1",
		 "policyName":"Pod Security Privileged Container",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls the ability of any container to enable privileged mode.",
		 "scheduled_policy":false,
		 "scriptId":"62",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"63",
		 "orgId":"1",
		 "policyName":"Pod Security Proc Mount",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Controls the allowed procMount types for the container.",
		 "scheduled_policy":false,
		 "scriptId":"63",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"64",
		 "orgId":"1",
		 "policyName":"Pod Security Read Only Root FS",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Requires the use of a read-only root file system by pod containers.",
		 "scheduled_policy":false,
		 "scriptId":"64",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"65",
		 "orgId":"1",
		 "policyName":"Pod Security Volume Types",
		 "category":"Pod Security",
		 "stage":"deploy",
		 "description":"Restricts mountable volume types to those specified by the user.",
		 "scheduled_policy":false,
		 "scriptId":"65",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"66",
		 "orgId":"1",
		 "policyName":"SonarQube Quality Gate Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"The purpose of this policy is to comply with SonarQube quality gates, ensuring that code meets predefined quality and performance standards. It emphasizes the importance of continuous code improvement and adherence to best practices.",
		 "scheduled_policy":false,
		 "scriptId":"66",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"67",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating E Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade E rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "scriptId":"67",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating E Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"68",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating D Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade D rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "scriptId":"68",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating D Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"69",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating C Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade C rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "scriptId":"69",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating C Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"70",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating B Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade B rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "scriptId":"70",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating B Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"71",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating E Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade E rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "scriptId":"71",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating E Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"72",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating D Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade D rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "scriptId":"72",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating D Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"73",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating C Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade C rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "scriptId":"73",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating C Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"74",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating B Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade B rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "scriptId":"74",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating B Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"75",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating E Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade E rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "scriptId":"75",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating E Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"76",
		 "orgId":"1",
		 "policyName":"High Vulnerability Prevention Policy",
		 "category":"Vulnerability Analysis",
		 "stage":"artifact",
		 "description":"High Severity Vulnerabilities should not be found in the artifact",
		 "scheduled_policy":true,
		 "scriptId":"76",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"77",
		 "orgId":"1",
		 "policyName":"CIS-1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The API server pod specification file controls various parameters that set the behavior of the API server. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"78",
		 "orgId":"1",
		 "policyName":"CIS-1.1.2 Ensure that the API server pod specification file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The API server pod specification file controls various parameters that set the behavior of the API server. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.2 Ensure that the API server pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"79",
		 "orgId":"1",
		 "policyName":"CIS-1.1.3 Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.3 Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"80",
		 "orgId":"1",
		 "policyName":"CIS-1.1.4 Ensure that the controller manager pod specification file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The controller manager pod specification file controls various parameters that set the behavior of various components of the master node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.4 Ensure that the controller manager pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"81",
		 "orgId":"1",
		 "policyName":"CIS-1.1.5 Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The scheduler pod specification file controls various parameters that set the behavior of the Scheduler service in the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.5 Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"82",
		 "orgId":"1",
		 "policyName":"CIS-1.1.6 Ensure that the scheduler pod specification file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The scheduler pod specification file controls various parameters that set the behavior of the kube-scheduler service in the master node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.6 Ensure that the scheduler pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"83",
		 "orgId":"1",
		 "policyName":"CIS-1.1.7 Ensure that the etcd pod specification file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The etcd pod specification file /etc/kubernetes/manifests/etcd.yaml controls various parameters that set the behavior of the etcd service in the master node. etcd is a highly-available key-value store which Kubernetes uses for persistent storage of all of its REST API object. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.7 Ensure that the etcd pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"84",
		 "orgId":"1",
		 "policyName":"CIS-1.1.8 Ensure that the etcd pod specification file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The etcd pod specification file /etc/kubernetes/manifests/etcd.yaml controls various parameters that set the behavior of the etcd service in the master node. etcd is a highly-available key-value store which Kubernetes uses for persistent storage of all of its REST API object. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.8 Ensure that the etcd pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"85",
		 "orgId":"1",
		 "policyName":"CIS-1.1.9 Ensure that the Container Network Interface file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Container Network Interface provides various networking options for overlay networking. You should consult their documentation and restrict their respective file permissions to maintain the integrity of those files. Those files should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.9 Ensure that the Container Network Interface file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"86",
		 "orgId":"1",
		 "policyName":"CIS-1.1.10 Ensure that the Container Network Interface file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Container Network Interface provides various networking options for overlay networking. You should consult their documentation and restrict their respective file permissions to maintain the integrity of those files. Those files should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.10 Ensure that the Container Network Interface file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"87",
		 "orgId":"1",
		 "policyName":"CIS-1.1.11 Ensure that the etcd data directory permissions are set to 700 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. This data directory should be protected from any unauthorized reads or writes. It should not be readable or writable by any group members or the world.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.11 Ensure that the etcd data directory permissions are set to 700 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"88",
		 "orgId":"1",
		 "policyName":"CIS-1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. This data directory should be protected from any unauthorized reads or writes. It should be owned by etcd:etcd.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"89",
		 "orgId":"1",
		 "policyName":"CIS-1.1.13 Ensure that the admin.conf file permissions are set to 600",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The admin.conf is the administrator kubeconfig file defining various settings for the administration of the cluster. This file contains private key and respective certificate allowed to fully manage the cluster. You should restrict its file permissions to maintain the integrity and confidentiality of the file. The file should be readable and writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.13 Ensure that the admin.conf file permissions are set to 600",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"90",
		 "orgId":"1",
		 "policyName":"CIS-1.1.14 Ensure that the admin.conf file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The admin.conf file contains the admin credentials for the cluster. You should set its file ownership to maintain the integrity and confidentiality of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.14 Ensure that the admin.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"91",
		 "orgId":"1",
		 "policyName":"CIS-1.1.15 Ensure that the scheduler.conf file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The scheduler.conf file is the kubeconfig file for the Scheduler. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.15 Ensure that the scheduler.conf file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"92",
		 "orgId":"1",
		 "policyName":"CIS-1.1.16 Ensure that the scheduler.conf file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The scheduler.conf file is the kubeconfig file for the Scheduler. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.16 Ensure that the scheduler.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"93",
		 "orgId":"1",
		 "policyName":"CIS-1.1.17 Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The controller-manager.conf file is the kubeconfig file for the Controller Manager. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.17 Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"94",
		 "orgId":"1",
		 "policyName":"CIS-1.1.18 Ensure that the controller-manager.conf file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The controller-manager.conf file is the kubeconfig file for the Controller Manager. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.18 Ensure that the controller-manager.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"95",
		 "orgId":"1",
		 "policyName":"CIS-1.1.19 Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes makes use of a number of certificates as part of its operation. You should set the ownership of the directory containing the PKI information and all files in that directory to maintain their integrity. The directory and files should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.19 Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"96",
		 "orgId":"1",
		 "policyName":"CIS-1.1.20 Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes makes use of a number of certificate files as part of the operation of its components. The permissions on these files should be set to 600 or more restrictive to protect their integrity.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.20 Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"97",
		 "orgId":"1",
		 "policyName":"CIS-1.1.21 Ensure that the Kubernetes PKI key file permissions are set to 600",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes makes use of a number of key files as part of the operation of its components. The permissions on these files should be set to 600 to protect their integrity and confidentiality.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.21 Ensure that the Kubernetes PKI key file permissions are set to 600",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"98",
		 "orgId":"1",
		 "policyName":"CIS-1.2.1 Ensure that the API Server --anonymous-auth argument is set to false",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests. If you are using RBAC authorization, it is generally considered reasonable to allow anonymous access to the API Server for health checks and discovery purposes, and hence this recommendation is not scored. However, you should consider whether anonymous discovery is an acceptable risk for your purposes.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.1 Ensure that the API Server --anonymous-auth argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"99",
		 "orgId":"1",
		 "policyName":"CIS-1.2.2 Ensure that the API Server --token-auth-file parameter is not set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The token-based authentication utilizes static tokens to authenticate requests to the apiserver. The tokens are stored in clear-text in a file on the apiserver, and cannot be revoked or rotated without restarting the apiserver. Hence, do not use static token-based authentication.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.2 Ensure that the API Server --token-auth-file parameter is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"100",
		 "orgId":"1",
		 "policyName":"CIS-1.2.3 Ensure that the API Server --DenyServiceExternalIPs is not set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"This admission controller rejects all net-new usage of the Service field externalIPs. This feature is very powerful ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.3 Ensure that the API Server --DenyServiceExternalIPs is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"101",
		 "orgId":"1",
		 "policyName":"CIS-1.2.4 Ensure that the API Server --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The apiserver, by default, does not authenticate itself to the kubelets HTTPS endpoints. The requests from the apiserver are treated anonymously. You should set up certificate-based kubelet authentication to ensure that the apiserver authenticates itself to kubelets when submitting requests.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.4 Ensure that the API Server --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"102",
		 "orgId":"1",
		 "policyName":"CIS-1.2.5 Ensure that the API Server --kubelet-certificate-authority argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.5 Ensure that the API Server --kubelet-certificate-authority argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"103",
		 "orgId":"1",
		 "policyName":"CIS-1.2.6 Ensure that the API Server --authorization-mode argument is not set to AlwaysAllow",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The API Server, can be configured to allow all requests. This mode should not be used on any production cluster.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.6 Ensure that the API Server --authorization-mode argument is not set to AlwaysAllow",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"104",
		 "orgId":"1",
		 "policyName":"CIS-1.2.7 Ensure that the API Server --authorization-mode argument includes Node",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The Node authorization mode only allows kubelets to read Secret, ConfigMap, PersistentVolume, and PersistentVolumeClaim objects associated with their nodes.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.7 Ensure that the API Server --authorization-mode argument includes Node",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"105",
		 "orgId":"1",
		 "policyName":"CIS-1.2.8 Ensure that the API Server --authorization-mode argument includes RBAC",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Role Based Access Control ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.8 Ensure that the API Server --authorization-mode argument includes RBAC",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"106",
		 "orgId":"1",
		 "policyName":"CIS-1.2.9 Ensure that the admission control plugin EventRateLimit is set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Using EventRateLimit admission control enforces a limit on the number of events that the API Server will accept in a given time slice. A misbehaving workload could overwhelm and DoS the API Server, making it unavailable. This particularly applies to a multi-tenant cluster, where there might be a small percentage of misbehaving tenants which could have a significant impact on the performance of the cluster overall. Hence, it is recommended to limit the rate of events that the API server will accept. Note: This is an Alpha feature in the Kubernetes 1.15 release.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"107",
		 "orgId":"1",
		 "policyName":"CIS-1.2.10 Ensure that the admission control plugin AlwaysAdmit is not set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Setting admission control plugin AlwaysAdmit allows all requests and do not filter any requests. The AlwaysAdmit admission controller was deprecated in Kubernetes v1.13. Its behavior was equivalent to turning off all admission controllers.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.10 Ensure that the admission control plugin AlwaysAdmit is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"108",
		 "orgId":"1",
		 "policyName":"CIS-1.2.11 Ensure that the admission control plugin AlwaysPullImages is set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Setting admission control policy to AlwaysPullImages forces every new pod to pull the required images every time. In a multi-tenant cluster users can be assured that their private images can only be used by those who have the credentials to pull them. Without this admission control policy, once an image has been pulled to a node, any pod from any user can use it simply by knowing the images name, without any authorization check against the image ownership. When this plug-in is enabled, images are always pulled prior to starting containers, which means valid credentials are required.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.11 Ensure that the admission control plugin AlwaysPullImages is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"109",
		 "orgId":"1",
		 "policyName":"CIS-1.2.12 Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"SecurityContextDeny can be used to provide a layer of security for clusters which do not have PodSecurityPolicies enabled.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.12 Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"110",
		 "orgId":"1",
		 "policyName":"CIS-1.2.13 Ensure that the admission control plugin ServiceAccount is set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"When you create a pod, if you do not specify a service account, it is automatically assigned the default service account in the same namespace. You should create your own service account and let the API server manage its security tokens.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.13 Ensure that the admission control plugin ServiceAccount is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"111",
		 "orgId":"1",
		 "policyName":"CIS-1.2.14 Ensure that the admission control plugin NamespaceLifecycle is set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Setting admission control policy to NamespaceLifecycle ensures that objects cannot be created in non-existent namespaces, and that namespaces undergoing termination are not used for creating the new objects. This is recommended to enforce the integrity of the namespace termination process and also for the availability of the newer objects.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.14 Ensure that the admission control plugin NamespaceLifecycle is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"112",
		 "orgId":"1",
		 "policyName":"CIS-1.2.15 Ensure that the admission control plugin NodeRestriction is set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Using the NodeRestriction plug-in ensures that the kubelet is restricted to the Node and Pod objects that it could modify as defined. Such kubelets will only be allowed to modify their own Node API object, and only modify Pod API objects that are bound to their node.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.15 Ensure that the admission control plugin NodeRestriction is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"113",
		 "orgId":"1",
		 "policyName":"CIS-1.2.16 Ensure that the API Server --secure-port argument is not set to 0",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The secure port is used to serve https with authentication and authorization. If you disable it, no https traffic is served and all traffic is served unencrypted.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.16 Ensure that the API Server --secure-port argument is not set to 0",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"114",
		 "orgId":"1",
		 "policyName":"CIS-1.2.17 Ensure that the API Server --profiling argument is set to false",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.17 Ensure that the API Server --profiling argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"115",
		 "orgId":"1",
		 "policyName":"CIS-1.2.18 Ensure that the API Server --audit-log-path argument is set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Auditing the Kubernetes API Server provides a security-relevant chronological set of records documenting the sequence of activities that have affected system by individual users, administrators or other components of the system. Even though currently, Kubernetes provides only basic audit capabilities, it should be enabled. You can enable it by setting an appropriate audit log path.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.18 Ensure that the API Server --audit-log-path argument is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"116",
		 "orgId":"1",
		 "policyName":"CIS-1.2.19 Ensure that the API Server --audit-log-maxage argument is set to 30 or as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Retaining logs for at least 30 days ensures that you can go back in time and investigate or correlate any events. Set your audit log retention period to 30 days or as per your business requirements.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.19 Ensure that the API Server --audit-log-maxage argument is set to 30 or as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"117",
		 "orgId":"1",
		 "policyName":"CIS-1.2.20 Ensure that the API Server --audit-log-maxbackup argument is set to 10 or as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes automatically rotates the log files. Retaining old log files ensures that you would have sufficient log data available for carrying out any investigation or correlation. For example, if you have set file size of 100 MB and the number of old log files to keep as 10, you would approximate have 1 GB of log data that you could potentially use for your analysis.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.20 Ensure that the API Server --audit-log-maxbackup argument is set to 10 or as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"118",
		 "orgId":"1",
		 "policyName":"CIS-1.2.21 Ensure that the API Server --audit-log-maxsize argument is set to 100 or as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes automatically rotates the log files. Retaining old log files ensures that you would have sufficient log data available for carrying out any investigation or correlation. If you have set file size of 100 MB and the number of old log files to keep as 10, you would approximate have 1 GB of log data that you could potentially use for your analysis.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.21 Ensure that the API Server --audit-log-maxsize argument is set to 100 or as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"119",
		 "orgId":"1",
		 "policyName":"CIS-1.2.22 Ensure that the API Server --request-timeout argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Setting global request timeout allows extending the API server request timeout limit to a duration appropriate to the users connection speed. By default, it is set to 60 seconds which might be problematic on slower connections making cluster resources inaccessible once the data volume for requests exceeds what can be transmitted in 60 seconds. But, setting this timeout limit to be too large can exhaust the API server resources making it prone to Denial-of-Service attack. Hence, it is recommended to set this limit as appropriate and change the default limit of 60 seconds only if needed.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.22 Ensure that the API Server --request-timeout argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"120",
		 "orgId":"1",
		 "policyName":"CIS-1.2.23 Ensure that the API Server --service-account-lookup argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"If --service-account-lookup is not enabled, the apiserver only verifies that the authentication token is valid, and does not validate that the service account token mentioned in the request is actually present in etcd. This allows using a service account token even after the corresponding service account is deleted. This is an example of time of check to time of use security issue.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.23 Ensure that the API Server --service-account-lookup argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"121",
		 "orgId":"1",
		 "policyName":"CIS-1.2.24 Ensure that the API Server --service-account-key-file argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"By default, if no --service-account-key-file is specified to the apiserver, it uses the private key from the TLS serving certificate to verify service account tokens. To ensure that the keys for service account tokens could be rotated as needed, a separate public/private key pair should be used for signing service account tokens. Hence, the public key should be specified to the apiserver with --service-account-key-file.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.24 Ensure that the API Server --service-account-key-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"122",
		 "orgId":"1",
		 "policyName":"CIS-1.2.25 Ensure that the API Server --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be protected by client authentication. This requires the API server to identify itself to the etcd server using a client certificate and key.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.25 Ensure that the API Server --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"123",
		 "orgId":"1",
		 "policyName":"CIS-1.2.26 Ensure that the API Server --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"API server communication contains sensitive parameters that should remain encrypted in transit. Configure the API server to serve only HTTPS traffic.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.26 Ensure that the API Server --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"124",
		 "orgId":"1",
		 "policyName":"CIS-1.2.27 Ensure that the API Server --client-ca-file argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"API server communication contains sensitive parameters that should remain encrypted in transit. Configure the API server to serve only HTTPS traffic. If --client-ca-file argument is set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.27 Ensure that the API Server --client-ca-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"125",
		 "orgId":"1",
		 "policyName":"CIS-1.2.28 Ensure that the API Server --etcd-cafile argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be protected by client authentication. This requires the API server to identify itself to the etcd server using a SSL Certificate Authority file.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.28 Ensure that the API Server --etcd-cafile argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"126",
		 "orgId":"1",
		 "policyName":"CIS-1.2.29 Ensure that the API Server --encryption-provider-config argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted at rest to avoid any disclosures.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.29 Ensure that the API Server --encryption-provider-config argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"127",
		 "orgId":"1",
		 "policyName":"CIS-1.2.30 Ensure that encryption providers are appropriately configured",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Where etcd encryption is used, it is important to ensure that the appropriate set of encryption providers is used. Currently, the aescbc, kms and secretbox are likely to be appropriate options.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.30 Ensure that encryption providers are appropriately configured",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"128",
		 "orgId":"1",
		 "policyName":"CIS-1.2.31 Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them. By default Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.2.31 Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"129",
		 "orgId":"1",
		 "policyName":"CIS-1.3.1 Ensure that the Controller Manager --terminated-pod-gc-threshold argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Garbage collection is important to ensure sufficient resource availability and avoiding degraded performance and availability. In the worst case, the system might crash or just be unusable for a long period of time. The current setting for garbage collection is 12,500 terminated pods which might be too high for your system to sustain. Based on your system resources and tests, choose an appropriate threshold value to activate garbage collection.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.1 Ensure that the Controller Manager --terminated-pod-gc-threshold argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"130",
		 "orgId":"1",
		 "policyName":"CIS-1.3.2 Ensure that the Controller Manager --profiling argument is set to false",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.2 Ensure that the Controller Manager --profiling argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"131",
		 "orgId":"1",
		 "policyName":"CIS-1.3.3 Ensure that the Controller Manager --use-service-account-credentials argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The controller manager creates a service account per controller in the kube-system namespace, generates a credential for it, and builds a dedicated API client with that service account credential for each controller loop to use. Setting the --use-service-account-credentials to true runs each control loop within the controller manager using a separate service account credential. When used in combination with RBAC, this ensures that the control loops run with the minimum permissions required to perform their intended tasks.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.3 Ensure that the Controller Manager --use-service-account-credentials argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"132",
		 "orgId":"1",
		 "policyName":"CIS-1.3.4 Ensure that the Controller Manager --service-account-private-key-file argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"To ensure that keys for service account tokens can be rotated as needed, a separate public/private key pair should be used for signing service account tokens. The private key should be specified to the controller manager with --service-account-private-key-file as appropriate.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.4 Ensure that the Controller Manager --service-account-private-key-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"133",
		 "orgId":"1",
		 "policyName":"CIS-1.3.5 Ensure that the Controller Manager --root-ca-file argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Processes running within pods that need to contact the API server must verify the API servers serving certificate. Failing to do so could be a subject to man-in-the-middle attacks. Providing the root certificate for the API servers serving certificate to the controller manager with the --root-ca-file argument allows the controller manager to inject the trusted bundle into pods so that they can verify TLS connections to the API server.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.5 Ensure that the Controller Manager --root-ca-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"134",
		 "orgId":"1",
		 "policyName":"CIS-1.3.6 Ensure that the Controller Manager RotateKubeletServerCertificate argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials and rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.6 Ensure that the Controller Manager RotateKubeletServerCertificate argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"135",
		 "orgId":"1",
		 "policyName":"CIS-1.3.7 Ensure that the Controller Manager --bind-address argument is set to 127.0.0.1",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The Controller Manager API service which runs on port 10252/TCP by default is used for health and metrics information and is available without authentication or encryption. As such it should only be bound to a localhost interface, to minimize the clusters attack surface.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.3.7 Ensure that the Controller Manager --bind-address argument is set to 127.0.0.1",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"136",
		 "orgId":"1",
		 "policyName":"CIS-1.4.1 Ensure that the Scheduler --profiling argument is set to false",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.4.1 Ensure that the Scheduler --profiling argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"137",
		 "orgId":"1",
		 "policyName":"CIS-1.4.2 Ensure that the Scheduler --bind-address argument is set to 127.0.0.1",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The Scheduler API service which runs on port 10251/TCP by default is used for health and metrics information and is available without authentication or encryption. As such it should only be bound to a localhost interface, to minimize the clusters attack surface.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.4.2 Ensure that the Scheduler --bind-address argument is set to 127.0.0.1",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"138",
		 "orgId":"1",
		 "policyName":"CIS-2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted in transit.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"139",
		 "orgId":"1",
		 "policyName":"CIS-2.2 Ensure that the --client-cert-auth argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication via valid certificates to secure the access to the etcd service.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.2 Ensure that the --client-cert-auth argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"140",
		 "orgId":"1",
		 "policyName":"CIS-2.3 Ensure that the --auto-tls argument is not set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication via valid certificates to secure the access to the etcd service.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.3 Ensure that the --auto-tls argument is not set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"141",
		 "orgId":"1",
		 "policyName":"CIS-2.4 Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted in transit and also amongst peers in the etcd clusters.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.4 Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"142",
		 "orgId":"1",
		 "policyName":"CIS-2.5 Ensure that the --peer-client-cert-auth argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.5 Ensure that the --peer-client-cert-auth argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"143",
		 "orgId":"1",
		 "policyName":"CIS-2.6 Ensure that the --peer-auto-tls argument is not set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. Hence, do not use self-signed certificates for authentication.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.6 Ensure that the --peer-auto-tls argument is not set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"144",
		 "orgId":"1",
		 "policyName":"CIS-2.7 Ensure that a unique Certificate Authority is used for etcd",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. Its access should be restricted to specifically designated clients and peers only. Authentication to etcd is based on whether the certificate presented was issued by a trusted certificate authority. There is no checking of certificate attributes such as common name or subject alternative name. As such, if any attackers were able to gain access to any certificate issued by the trusted certificate authority, they would be able to gain full access to the etcd database.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-2.7 Ensure that a unique Certificate Authority is used for etcd",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"145",
		 "orgId":"1",
		 "policyName":"CIS-3.2.1 Ensure that a minimal audit policy is created",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes can audit the details of requests made to the API server. The --audit-policy-file flag must be set for this logging to be enabled.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-3.2.1 Ensure that a minimal audit policy is created",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"146",
		 "orgId":"1",
		 "policyName":"CIS-3.2.2 Ensure that the audit policy covers key security concerns",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Security audit logs should cover access and modification of key resources in the cluster, to enable them to form an effective part of a security environment.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-3.2.2 Ensure that the audit policy covers key security concerns",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"147",
		 "orgId":"1",
		 "policyName":"CIS-4.1.1 Ensure that the kubelet service file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubelet service file controls various parameters that set the behavior of the kubelet service in the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.1 Ensure that the kubelet service file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"148",
		 "orgId":"1",
		 "policyName":"CIS-4.1.2 Ensure that the kubelet service file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubelet service file controls various parameters that set the behavior of the kubelet service in the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.2 Ensure that the kubelet service file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"149",
		 "orgId":"1",
		 "policyName":"CIS-4.1.3 If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kube-proxy kubeconfig file controls various parameters of the kube-proxy service in the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system. It is possible to run kube-proxy with the kubeconfig parameters configured as a Kubernetes ConfigMap instead of a file. In this case, there is no proxy kubeconfig file.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.3 If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"150",
		 "orgId":"1",
		 "policyName":"CIS-4.1.4 If proxy kubeconfig file exists ensure ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubeconfig file for kube-proxy controls various parameters for the kube-proxy service in the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.4 If proxy kubeconfig file exists ensure ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"151",
		 "orgId":"1",
		 "policyName":"CIS-4.1.5 Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubelet.conf file is the kubeconfig file for the node, and controls various parameters that set the behavior and identity of the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.5 Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"152",
		 "orgId":"1",
		 "policyName":"CIS-4.1.6 Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubelet.conf file is the kubeconfig file for the node, and controls various parameters that set the behavior and identity of the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.6 Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"153",
		 "orgId":"1",
		 "policyName":"CIS-4.1.7 Ensure that the certificate authorities file permissions are set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The certificate authorities file controls the authorities used to validate API requests. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.7 Ensure that the certificate authorities file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"154",
		 "orgId":"1",
		 "policyName":"CIS-4.1.8 Ensure that the client certificate authorities file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The certificate authorities file controls the authorities used to validate API requests. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.8 Ensure that the client certificate authorities file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"155",
		 "orgId":"1",
		 "policyName":"CIS-4.1.9 If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubelet reads various parameters, including security settings, from a config file specified by the --config argument. If this file is specified you should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.9 If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"156",
		 "orgId":"1",
		 "policyName":"CIS-4.1.10 If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The kubelet reads various parameters, including security settings, from a config file specified by the --config argument. If this file is specified you should restrict its file permissions to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.1.10 If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"157",
		 "orgId":"1",
		 "policyName":"CIS-4.2.1 Ensure that the --anonymous-auth argument is set to false",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the Kubelet server. You should rely on authentication to authorize access and disallow anonymous requests.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.1 Ensure that the --anonymous-auth argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"158",
		 "orgId":"1",
		 "policyName":"CIS-4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubelets, by default, allow all authenticated requests (even anonymous ones) without needing explicit authorization checks from the apiserver. You should restrict this behavior and only allow explicitly authorized requests.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"159",
		 "orgId":"1",
		 "policyName":"CIS-4.2.3 Ensure that the --client-ca-file argument is set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and using the kubelet\u2019s port-forwarding functionality. These connections terminate at the kubelet\u2019s HTTPS endpoint. By default, the apiserver does not verify the kubelet\u2019s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks. Enabling Kubelet certificate authentication ensures that the apiserver could authenticate the Kubelet before submitting any requests.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.3 Ensure that the --client-ca-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"160",
		 "orgId":"1",
		 "policyName":"CIS-4.2.4 Verify that the --read-only-port argument is set to 0",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The Kubelet process provides a read-only API in addition to the main Kubelet API. Unauthenticated access is provided to this read-only API which could possibly retrieve potentially sensitive information about the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.4 Verify that the --read-only-port argument is set to 0",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"161",
		 "orgId":"1",
		 "policyName":"CIS-4.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Setting idle timeouts ensures that you are protected against Denial-of-Service attacks, inactive connections and running out of ephemeral ports. Note: By default, --streaming-connection-idle-timeout is set to 4 hours which might be too high for your environment. Setting this as appropriate would additionally ensure that such streaming connections are timed out after serving legitimate use cases.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"162",
		 "orgId":"1",
		 "policyName":"CIS-4.2.6 Ensure that the --protect-kernel-defaults argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kernel parameters are usually tuned and hardened by the system administrators before putting the systems into production. These parameters protect the kernel and the system. Your kubelet kernel defaults that rely on such parameters should be appropriately set to match the desired secured system state. Ignoring this could potentially lead to running pods with undesired kernel behavior.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.6 Ensure that the --protect-kernel-defaults argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"163",
		 "orgId":"1",
		 "policyName":"CIS-4.2.7 Ensure that the --make-iptables-util-chains argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubelets can automatically manage the required changes to iptables based on how you choose your networking options for the pods. It is recommended to let kubelets manage the changes to iptables. This ensures that the iptables configuration remains in sync with pods networking configuration. Manually configuring iptables with dynamic pod network configuration changes might hamper the communication between pods/containers and to the outside world. You might have iptables rules too restrictive or too open.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.7 Ensure that the --make-iptables-util-chains argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"164",
		 "orgId":"1",
		 "policyName":"CIS-4.2.8 Ensure that the --hostname-override argument is not set",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Overriding hostnames could potentially break TLS setup between the kubelet and the apiserver. Additionally, with overridden hostnames, it becomes increasingly difficult to associate logs with a particular node and process them for security analytics. Hence, you should setup your kubelet nodes with resolvable FQDNs and avoid overriding the hostnames with IPs.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.8 Ensure that the --hostname-override argument is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"165",
		 "orgId":"1",
		 "policyName":"CIS-4.2.9 Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"It is important to capture all events and not restrict event creation. Events are an important source of security information and analytics that ensure that your environment is consistently monitored using the event data.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.9 Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"166",
		 "orgId":"1",
		 "policyName":"CIS-4.2.10 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and using the kubelet\u2019s port-forwarding functionality. These connections terminate at the kubelet\u2019s HTTPS endpoint. By default, the apiserver does not verify the kubelet\u2019s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.10 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"167",
		 "orgId":"1",
		 "policyName":"CIS-4.2.11 Ensure that the --rotate-certificates argument is not set to false",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The --rotate-certificates setting causes the kubelet to rotate its client certificates by creating new CSRs as its existing credentials expire. This automated periodic rotation ensures that the there is no downtime due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.11 Ensure that the --rotate-certificates argument is not set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"168",
		 "orgId":"1",
		 "policyName":"CIS-4.2.12 Verify that the RotateKubeletServerCertificate argument is set to true",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials and rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.12 Verify that the RotateKubeletServerCertificate argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"169",
		 "orgId":"1",
		 "policyName":"CIS-4.2.13 Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them. By default Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-4.2.13 Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"170",
		 "orgId":"1",
		 "policyName":"CIS-5.1.1 Ensure that the cluster-admin role is only used where required",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes provides a set of default roles where RBAC is used. Some of these roles such as cluster-admin provide wide-ranging privileges which should only be applied where absolutely necessary. Roles such as cluster-admin allow super-user access to perform any action on any resource. When used in a ClusterRoleBinding, it gives full control over every resource in the cluster and in all namespaces. When used in a RoleBinding, it gives full control over every resource in the rolebindings namespace, including the namespace itself.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.1 Ensure that the cluster-admin role is only used where required",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"171",
		 "orgId":"1",
		 "policyName":"CIS-5.1.2 Minimize access to secrets",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Inappropriate access to secrets stored within the Kubernetes cluster can allow for an attacker to gain additional access to the Kubernetes cluster or external resources whose credentials are stored as secrets.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.2 Minimize access to secrets",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"172",
		 "orgId":"1",
		 "policyName":"CIS-5.1.3 Minimize wildcard use in Roles and ClusterRoles",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The principle of least privilege recommends that users are provided only the access required for their role and nothing more. The use of wildcard rights grants is likely to provide excessive rights to the Kubernetes API.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.3 Minimize wildcard use in Roles and ClusterRoles",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"173",
		 "orgId":"1",
		 "policyName":"CIS-5.1.4 Minimize access to create pods",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The ability to create pods in a cluster opens up possibilities for privilege escalation and should be restricted, where possible.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.4 Minimize access to create pods",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"174",
		 "orgId":"1",
		 "policyName":"CIS-5.1.5 Ensure that default service accounts are not actively used",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes provides a default service account which is used by cluster workloads where no specific service account is assigned to the pod. Where access to the Kubernetes API from a pod is required, a specific service account should be created for that pod, and rights granted to that service account. The default service account should be configured such that it does not provide a service account token and does not have any explicit rights assignments.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.5 Ensure that default service accounts are not actively used",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"175",
		 "orgId":"1",
		 "policyName":"CIS-5.1.6 Ensure that Service Account Tokens are only mounted where necessary",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Mounting service account tokens inside pods can provide an avenue for privilege escalation attacks where an attacker is able to compromise a single pod in the cluster. Avoiding mounting these tokens removes this attack avenue.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.6 Ensure that Service Account Tokens are only mounted where necessary",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"176",
		 "orgId":"1",
		 "policyName":"CIS-5.1.8 Limit use of the Bind",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"The impersonate privilege allows a subject to impersonate other users gaining their rights to the cluster. The bind privilege allows the subject to add a binding to a cluster role or role which escalates their effective permissions in the cluster. The escalate privilege allows a subject to modify cluster roles to which they are bound, increasing their rights to that level. Each of these permissions has the potential to allow for privilege escalation to cluster-admin level.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"177",
		 "orgId":"1",
		 "policyName":"CIS-5.2.1 Ensure that the cluster has at least one active policy control mechanism in place",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Without an active policy control mechanism, it is not possible to limit the use of containers with access to underlying cluster nodes, via mechanisms like privileged containers, or the use of hostPath volume mounts.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.1 Ensure that the cluster has at least one active policy control mechanism in place",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"178",
		 "orgId":"1",
		 "policyName":"CIS-5.2.2 Minimize the admission of privileged containers",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Privileged containers have access to all Linux Kernel capabilities and devices. A container running with full privileges can do almost everything that the host can do. This flag exists to allow special use-cases, like manipulating the network stack and accessing devices. There should be at least one admission control policy defined which does not permit privileged containers. If you need to run privileged containers, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.2 Minimize the admission of privileged containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"179",
		 "orgId":"1",
		 "policyName":"CIS-5.2.3 Minimize the admission of containers wishing to share the host process ID namespace",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A container running in the hosts PID namespace can inspect processes running outside the container. If the container also has access to ptrace capabilities this can be used to escalate privileges outside of the container. There should be at least one admission control policy defined which does not permit containers to share the host PID namespace. If you need to run containers which require hostPID, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.3 Minimize the admission of containers wishing to share the host process ID namespace",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"180",
		 "orgId":"1",
		 "policyName":"CIS-5.2.4 Minimize the admission of containers wishing to share the host IPC namespace",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A container running in the hosts IPC namespace can use IPC to interact with processes outside the container. There should be at least one admission control policy defined which does not permit containers to share the host IPC namespace. If you need to run containers which require hostIPC, this should be definited in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.4 Minimize the admission of containers wishing to share the host IPC namespace",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"181",
		 "orgId":"1",
		 "policyName":"CIS-5.2.5 Minimize the admission of containers wishing to share the host network namespace",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A container running in the hosts network namespace could access the local loopback device, and could access network traffic to and from other pods. There should be at least one admission control policy defined which does not permit containers to share the host network namespace. If you need to run containers which require access to the hosts network namesapces, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.5 Minimize the admission of containers wishing to share the host network namespace",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"182",
		 "orgId":"1",
		 "policyName":"CIS-5.2.6 Minimize the admission of containers with allowPrivilegeEscalation",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A container running with the allowPrivilegeEscalation flag set to true may have processes that can gain more privileges than their parent. There should be at least one admission control policy defined which does not permit containers to allow privilege escalation. The option exists ",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.6 Minimize the admission of containers with allowPrivilegeEscalation",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"183",
		 "orgId":"1",
		 "policyName":"CIS-5.2.7 Minimize the admission of root containers",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Containers may run as any Linux user. Containers which run as the root user, whilst constrained by Container Runtime security features still have a escalated likelihood of container breakout. Ideally, all containers should run as a defined non-UID 0 user. There should be at least one admission control policy defined which does not permit root containers. If you need to run root containers, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.7 Minimize the admission of root containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"184",
		 "orgId":"1",
		 "policyName":"CIS-5.2.8 Minimize the admission of containers with the NET_RAW capability",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Containers run with a default set of capabilities as assigned by the Container Runtime. By default this can include potentially dangerous capabilities. With Docker as the container runtime the NET_RAW capability is enabled which may be misused by malicious containers. Ideally, all containers should drop this capability. There should be at least one admission control policy defined which does not permit containers with the NET_RAW capability. If you need to run containers with this capability, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.8 Minimize the admission of containers with the NET_RAW capability",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"185",
		 "orgId":"1",
		 "policyName":"CIS-5.2.9 Minimize the admission of containers with added capabilities",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities outside this set can be added to containers which could expose them to risks of container breakout attacks. There should be at least one policy defined which prevents containers with capabilities beyond the default set from launching. If you need to run containers with additional capabilities, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.9 Minimize the admission of containers with added capabilities",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"186",
		 "orgId":"1",
		 "policyName":"CIS-5.2.10 Minimize the admission of containers with capabilities assigned",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities are parts of the rights generally granted on a Linux system to the root user. In many cases applications running in containers do not require any capabilities to operate, so from the perspective of the principal of least privilege use of capabilities should be minimized.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.10 Minimize the admission of containers with capabilities assigned",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"187",
		 "orgId":"1",
		 "policyName":"CIS-5.2.11 Minimize the admission of Windows HostProcess Containers",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A Windows container making use of the hostProcess flag can interact with the underlying Windows cluster node. As per the Kubernetes documentation, this provides \"privileged access\" to the Windows node.\n\n Where Windows containers are used inside a Kubernetes cluster, there should be at least one admission control policy which does not permit hostProcess Windows containers.\n\n If you need to run Windows containers which require hostProcess, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.11 Minimize the admission of Windows HostProcess Containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"188",
		 "orgId":"1",
		 "policyName":"CIS-5.2.12 Minimize the admission of HostPath volumes",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A container which mounts a hostPath volume as part of its specification will have access to the filesystem of the underlying cluster node. The use of hostPath volumes may allow containers access to privileged areas of the node filesystem. There should be at least one admission control policy defined which does not permit containers to mount hostPath volumes. If you need to run containers which require hostPath volumes, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.12 Minimize the admission of HostPath volumes",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"189",
		 "orgId":"1",
		 "policyName":"CIS-5.2.13 Minimize the admission of containers which use HostPorts",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Host ports connect containers directly to the hosts network. This can bypass controls such as network policy. There should be at least one admission control policy defined which does not permit containers which require the use of HostPorts. If you need to run containers which require HostPorts, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.2.13 Minimize the admission of containers which use HostPorts",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"190",
		 "orgId":"1",
		 "policyName":"CIS-5.3.1 Ensure that the CNI in use supports Network Policies",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes network policies are enforced by the CNI plugin in use. As such it is important to ensure that the CNI plugin supports both Ingress and Egress network policies.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.3.1 Ensure that the CNI in use supports Network Policies",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"191",
		 "orgId":"1",
		 "policyName":"CIS-5.3.2 Ensure that all Namespaces have Network Policies defined",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Running different applications on the same Kubernetes cluster creates a risk of one compromised application attacking a neighboring application. Network segmentation is important to ensure that containers can communicate only with those they are supposed to. A network policy is a specification of how selections of pods are allowed to communicate with each other and other network endpoints. Network Policies are namespace scoped. When a network policy is introduced to a given namespace, all traffic not allowed by the policy is denied. However, if there are no network policies in a namespace all traffic will be allowed into and out of the pods in that namespace.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.3.2 Ensure that all Namespaces have Network Policies defined",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"192",
		 "orgId":"1",
		 "policyName":"CIS-5.4.1 Prefer using secrets as files over secrets as environment variables",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"It is reasonably common for application code to log out its environment (particularly in the event of an error). This will include any secret values passed in as environment variables, so secrets can easily be exposed to any user or entity who has access to the logs.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.4.1 Prefer using secrets as files over secrets as environment variables",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"193",
		 "orgId":"1",
		 "policyName":"CIS-5.4.2 Consider external secret storage",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Kubernetes supports secrets as first-class objects, but care needs to be taken to ensure that access to secrets is carefully limited. Using an external secrets provider can ease the management of access to secrets, especially where secrets are used across both Kubernetes and non-Kubernetes environments.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.4.2 Consider external secret storage",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"194",
		 "orgId":"1",
		 "policyName":"CIS-5.7.1 Create administrative boundaries between resources using namespaces",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. A Kubernetes namespace allows you to partition created resources into logically named groups. Resources created in one namespace can be hidden from other namespaces. By default, each resource created by a user in Kubernetes cluster runs in a default namespace, called default. You can create additional namespaces and attach resources and users to them. You can use Kubernetes Authorization plugins to create policies that segregate access to namespace resources between different users.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.7.1 Create administrative boundaries between resources using namespaces",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"195",
		 "orgId":"1",
		 "policyName":"CIS-5.7.2 Ensure that the seccomp profile is set to docker/default in your pod definitions",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Seccomp (secure computing mode) is used to restrict the set of system calls applications can make, allowing cluster administrators greater control over the security of workloads running in the cluster. Kubernetes disables seccomp profiles by default for historical reasons. You should enable it to ensure that the workloads have restricted actions available within the container.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.7.2 Ensure that the seccomp profile is set to docker/default in your pod definitions",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"196",
		 "orgId":"1",
		 "policyName":"CIS-5.7.3 Apply Security Context to Your Pods and Containers",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container. When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes. A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the pod/container/volume. There are two levels of security context: pod level security context, and container level security context.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.7.3 Apply Security Context to Your Pods and Containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"197",
		 "orgId":"1",
		 "policyName":"CIS-5.7.4 The default namespace should not be used",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Resources in a Kubernetes cluster should be segregated by namespace, to allow for security controls to be applied at that level and to make it easier to manage resources.",
		 "scheduled_policy":false,
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-5.7.4 The default namespace should not be used",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"198",
		 "orgId":"1",
		 "policyName":"C-0002 - MITRE - Exec into container",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Attackers who have permissions, can run malicious commands in containers in the cluster using exec command. In this method, attackers can use legitimate images, such as an OS image as a backdoor container, and run their malicious code remotely by using kubectl exec.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0002 - MITRE - Exec into container",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"199",
		 "orgId":"1",
		 "policyName":"C-0007 - MITRE - Data Destruction",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Attackers may attempt to destroy data and resources in the cluster. This includes deleting deployments, configurations, storage, and compute resources.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0007 - MITRE - Data Destruction",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"200",
		 "orgId":"1",
		 "policyName":"C-0012 - MITRE - Applications credentials in configuration files",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Such behavior is commonly seen in clusters that are monitored by Azure Security Center. Attackers who have access to those configurations, by querying the API server or by accessing those files on the developers endpoint, can steal the stored secrets and use them.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0012 - MITRE - Applications credentials in configuration files",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"201",
		 "orgId":"1",
		 "policyName":"C-0014 - MITRE - Access Kubernetes dashboard",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"The Kubernetes dashboard is a web-based UI that is used for monitoring and managing the Kubernetes cluster. The dashboard allows users to perform actions in the cluster using its service account with the permissions that are determined by the binding or cluster-binding for this service account. Attackers who gain access to a container in the cluster, can use its network access to the dashboard pod. Consequently, attackers may retrieve information about the various resources in the cluster using the dashboards identity.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0014 - MITRE - Access Kubernetes dashboard",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"202",
		 "orgId":"1",
		 "policyName":"C-0015 - MITRE - List Kubernetes secrets",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Secrets can be consumed by reference in the pod configuration. Attackers who have permissions to retrieve the secrets from the API server can access sensitive information that might include credentials to various services.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0015 - MITRE - List Kubernetes secrets",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"203",
		 "orgId":"1",
		 "policyName":"C-0020 - MITRE - Mount service principal",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"When the cluster is deployed in the cloud, in some cases attackers can leverage their access to a container in the cluster to gain cloud credentials. For example, in AKS each node contains service principal credential.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0020 - MITRE - Mount service principal",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"204",
		 "orgId":"1",
		 "policyName":"C-0021 - MITRE - Exposed sensitive interfaces",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Exposing a sensitive interface to the internet poses a security risk. Some popular frameworks were not intended to be exposed to the internet, and therefore dont require authentication by default. Thus, exposing them to the internet allows unauthenticated access to a sensitive interface which might enable running code or deploying containers in the cluster by a malicious actor. Examples of such interfaces that were seen exploited include Apache NiFi, Kubeflow, Argo Workflows, Weave Scope, and the Kubernetes dashboard.Note, this control is configurable. See below the details.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0021 - MITRE - Exposed sensitive interfaces",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"205",
		 "orgId":"1",
		 "policyName":"C-0026 - MITRE - Kubernetes CronJob",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Kubernetes Job is a controller that creates one or more pods and ensures that a specified number of them successfully terminate. Kubernetes Job can be used to run containers that perform finite tasks for batch jobs. Kubernetes CronJob is used to schedule Jobs. Attackers may use Kubernetes CronJob for scheduling execution of malicious code that would run as a container in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0026 - MITRE - Kubernetes CronJob",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"206",
		 "orgId":"1",
		 "policyName":"C-0031 - MITRE - Delete Kubernetes events",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Kubernetes events can be very useful for identifying changes that occur in the cluster. Therefore, attackers may want to delete these events by using kubectl delete events–all in an attempt to avoid detection of their activity in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0031 - MITRE - Delete Kubernetes events ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"207",
		 "orgId":"1",
		 "policyName":"C-0035 - MITRE - Cluster-admin binding",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Role-based access control is a key security feature in Kubernetes. RBAC can restrict the allowed actions of the various identities in the cluster. Cluster-admin is a built-in high privileged role in Kubernetes. Attackers who have permissions to create bindings and cluster-bindings in the cluster can create a binding to the cluster-admin ClusterRole or to other high privileges roles.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0035 - MITRE - Cluster-admin binding ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"208",
		 "orgId":"1",
		 "policyName":"C-0036 - MITRE - Validate Validating admission controller",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Attackers can use validating webhooks to intercept and discover all the resources in the cluster. This control lists all the validating webhook configurations that must be verified.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0036 - MITRE - Validate Validating admission controller",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"209",
		 "orgId":"1",
		 "policyName":"C-0037 - MITRE - CoreDNS poisoning",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"CoreDNS is a modular Domain Name System (DNS) server written in Go, hosted by Cloud Native Computing Foundation (CNCF). CoreDNS is the main DNS service that is being used in Kubernetes. The configuration of CoreDNS can be modified by a file named corefile. In Kubernetes, this file is stored in a ConfigMap object, located at the kube-system namespace. If attackers have permissions to modify the ConfigMap, for example by using the container\u2019s service account, they can change the behavior of the cluster\u2019s DNS, poison it, and take the network identity of other services.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0037 - MITRE - CoreDNS poisoning ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"210",
		 "orgId":"1",
		 "policyName":"C-0039 - MITRE - Validate Mutating admission controller",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Attackers may use mutating webhooks to intercept and modify all the resources in the cluster. This control lists all mutating webhook configurations that must be verified.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0039 - MITRE - Validate Mutating admission controller ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"211",
		 "orgId":"1",
		 "policyName":"C-0042 - MITRE - SSH server running inside container",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"SSH server that is running inside a container may be used by attackers. If attackers gain valid credentials to a container, whether by brute force attempts or by other methods such as phishing, they can use it to get remote access to the container by SSH.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0042 - MITRE - SSH server running inside container ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"212",
		 "orgId":"1",
		 "policyName":"C-0045 - MITRE - Writable hostPath mount",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"hostPath volume mounts a directory or a file from the host to the container. Attackers who have permissions to create a new container in the cluster may create one with a writable hostPath volume and gain persistence on the underlying host. For example, the latter can be achieved by creating a cron job on the host.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0045 - MITRE - Writable hostPath mount ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"213",
		 "orgId":"1",
		 "policyName":"C-0048 - MITRE - HostPath mount",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Mounting host directory to the container can be used by attackers to get access to the underlying host. This control identifies all the pods using hostPath mount.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0048 - MITRE - HostPath mount ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"214",
		 "orgId":"1",
		 "policyName":"C-0052 - MITRE - Instance Metadata API",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Cloud providers provide instance metadata service for retrieving information about the virtual machine, such as network configuration, disks, and SSH public keys. This service is accessible to the VMs via a non-routable IP address that can be accessed from within the VM only. Attackers who gain access to a container, may query the metadata API service for getting information about the underlying node.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0052 - MITRE - Instance Metadata API ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"215",
		 "orgId":"1",
		 "policyName":"C-0053 - MITRE - Access container service account",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Service account (SA) represents an application identity in Kubernetes. By default, an SA is mounted to every created pod in the cluster. Using the SA, containers in the pod can send requests to the Kubernetes API server. Attackers who get access to a pod can access the SA token (located in /var/run/secrets/kubernetes.io/serviceaccount/token) and perform actions in the cluster, according to the SA permissions. If RBAC is not enabled, the SA has unlimited permissions in the cluster. If RBAC is enabled, its permissions are determined by the RoleBindings\\\\ClusterRoleBindings that are associated with it.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0053 - MITRE - Access container service account ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"216",
		 "orgId":"1",
		 "policyName":"C-0054 - MITRE - Cluster internal networking",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Kubernetes networking behavior allows traffic between pods in the cluster as a default behavior. Attackers who gain access to a single container may use it for network reachability to another container in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0054 - MITRE - Cluster internal networking ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"217",
		 "orgId":"1",
		 "policyName":"C-0057 - MITRE - Privileged container",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"A privileged container is a container that has all the capabilities of the host machine, which lifts all the limitations regular containers have. Practically, this means that privileged containers can do almost every action that can be performed directly on the host. Attackers who gain access to a privileged container or have permissions to create a new privileged container ",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0057 - MITRE - Privileged container ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"218",
		 "orgId":"1",
		 "policyName":"C-0058 - MITRE - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0058 - MITRE - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"219",
		 "orgId":"1",
		 "policyName":"C-0059 - MITRE - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0059 - MITRE - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"220",
		 "orgId":"1",
		 "policyName":"C-0066 - MITRE - Secret/etcd encryption enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"etcd is a consistent and highly-available key value store used as Kubernetes backing store for all cluster data. All object data in Kubernetes, like secrets, are stored there. This is the reason why it is important to protect the contents of etcd and use its data encryption feature.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0066 - MITRE - Secret/etcd encryption enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"221",
		 "orgId":"1",
		 "policyName":"C-0067 - MITRE - Audit logs enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Audit logging is an important security feature in Kubernetes, it enables the operator to track requests to the cluster. It is important to use it so the operator has a record of events happened in Kubernetes.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0067 - MITRE - Audit logs enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"222",
		 "orgId":"1",
		 "policyName":"C-0068 - MITRE - PSP enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Pod Security Policies enable fine-grained authorization of pod creation and updates and it extends authorization beyond RBAC. It is an important to use PSP to control the creation of sensitive pods in your cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0068 - MITRE - PSP enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"223",
		 "orgId":"1",
		 "policyName":"C-0069 - MITRE - Disable anonymous access to Kubelet service",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"By default, requests to the kubelets HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of system:anonymous and a group of system:unauthenticated.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0069 - MITRE - Disable anonymous access to Kubelet service",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"224",
		 "orgId":"1",
		 "policyName":"C-0070 - MITRE - Enforce Kubelet client TLS authentication",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Kubelets are the node level orchestrator in Kubernetes control plane. They are publishing service port 10250 where they accept commands from API server. Operator must make sure that only API server is allowed to submit commands to Kubelet. This is done through client certificate verification, must configure Kubelet with client CA file to use for this purpose.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0070 - MITRE - Enforce Kubelet client TLS authentication",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"225",
		 "orgId":"1",
		 "policyName":"C-0002 - NSA - Exec into container",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Attackers who have permissions, can run malicious commands in containers in the cluster using exec command. In this method, attackers can use legitimate images, such as an OS image as a backdoor container, and run their malicious code remotely by using kubectl exec.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0002 - NSA - Exec into container",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"226",
		 "orgId":"1",
		 "policyName":"C-0005 - NSA - API server insecure port is enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"The control plane is the core of Kubernetes and gives users the ability to view containers, schedule new Pods, read Secrets, and execute commands in the cluster. Therefore, it should be protected. It is recommended to avoid control plane exposure to the Internet or to an untrusted network. The API server runs on ports 6443 and 8080. We recommend to block them in the firewall. Note also that port 8080, when accessed through the local machine, does not require TLS encryption, and the requests bypass authentication and authorization modules.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0005 - NSA - API server insecure port is enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"227",
		 "orgId":"1",
		 "policyName":"C-0009 - NSA - Resource limits",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"CPU and memory resources should have a limit set for every container or a namespace to prevent resource exhaustion. This control identifies all the pods without resource limit definitions by checking their yaml definition file as well as their namespace LimitRange objects. It is also recommended to use ResourceQuota object to restrict overall namespace resources, but this is not verified by this control.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0009 - NSA - Resource limits",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"228",
		 "orgId":"1",
		 "policyName":"C-0012 - NSA - Applications credentials in configuration files",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Such behavior is commonly seen in clusters that are monitored by Azure Security Center. Attackers who have access to those configurations, by querying the API server or by accessing those files on the developers endpoint, can steal the stored secrets and use them.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0012 - NSA - Applications credentials in configuration files",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"229",
		 "orgId":"1",
		 "policyName":"C-0013 - NSA - Non-root containers",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Container engines allow containers to run applications as a non-root user with non-root group membership. Typically, this non-default setting is configured when the container image is built. . Alternatively, Kubernetes can load containers into a Pod with SecurityContext:runAsUser specifying a non-zero user. While the runAsUser directive effectively forces non-root execution at deployment, NSA and CISA encourage developers to build container applications to execute as a non-root user. Having non-root execution integrated at build time provides better assurance that applications will function correctly without root privileges.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0013 - NSA - Non-root containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"230",
		 "orgId":"1",
		 "policyName":"C-0016 - NSA - Allow privilege escalation",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Attackers may gain access to a container and uplift its privilege to enable excessive capabilities.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0016 - NSA - Allow privilege escalation",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"231",
		 "orgId":"1",
		 "policyName":"C-0017 - NSA - Immutable container filesystem",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"By default, containers are permitted mostly unrestricted execution within their own context. An attacker who has access to a container, can create files and download scripts as he wishes, and modify the underlying application running on the container.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0017 - NSA - Immutable container filesystem",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"232",
		 "orgId":"1",
		 "policyName":"C-0030 - NSA - Ingress and Egress blocked",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Network policies control traffic flow between Pods, namespaces, and external IP addresses. By default, no network policies are applied to Pods or namespaces, resulting in unrestricted ingress and egress traffic within the Pod network. Pods become isolated through a network policy that applies to the Pod or the Pods namespace. Once a Pod is selected in a network policy, it rejects any connections that are not specifically allowed by any applicable policy object.Administrators should use a default policy selecting all Pods to deny all ingress and egress traffic and ensure any unselected Pods are isolated. Additional policies could then relax these restrictions for permissible connections.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0030 - NSA - Ingress and Egress blocked",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"233",
		 "orgId":"1",
		 "policyName":"C-0034 - NSA - Automatic mapping of service account",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Check all service accounts on which automount is not disabled. Check all workloads on which they and their service account dont disable automount.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0034 - NSA - Automatic mapping of service account",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"234",
		 "orgId":"1",
		 "policyName":"C-0035 - NSA - Cluster-admin binding",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Role-based access control (RBAC) is a key security feature in Kubernetes. RBAC can restrict the allowed actions of the various identities in the cluster. Cluster-admin is a built-in high privileged role in Kubernetes. Attackers who have permissions to create bindings and cluster-bindings in the cluster can create a binding to the cluster-admin ClusterRole or to other high privileges roles.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0035 - NSA - Cluster-admin binding",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"235",
		 "orgId":"1",
		 "policyName":"C-0038 - NSA - Host PID/IPC privileges",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Containers should be isolated from the host machine as much as possible. The hostPID and hostIPC fields in deployment yaml may allow cross-container influence and may expose the host itself to potentially malicious or destructive actions. This control identifies all pods using hostPID or hostIPC privileges.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0038 - NSA - Host PID/IPC privileges",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"236",
		 "orgId":"1",
		 "policyName":"C-0041 - NSA - HostNetwork access",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Potential attackers may gain access to a pod and inherit access to the entire host network. For example, in AWS case, they will have access to the entire VPC. This control identifies all the pods with host network access enabled.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0041 - NSA - HostNetwork access",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"237",
		 "orgId":"1",
		 "policyName":"C-0044 - NSA - Container hostPort",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Workloads that contain a container with hostport. The problem that arises is that if the scale of your workload is larger than the number of nodes in your Kubernetes cluster, the deployment fails. And any two workloads that specify the same HostPort cannot be deployed to the same node. In addition, if the host where your pods are running becomes unavailable, Kubernetes reschedules the pods to different nodes. Thus, if the IP address for your workload changes, external clients of your application will lose access to the pod. The same thing happens when you restart your pods — Kubernetes reschedules them to a different node if available.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0044 - NSA - Container hostPort",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"238",
		 "orgId":"1",
		 "policyName":"C-0046 - NSA - Insecure capabilities",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Giving insecure and unnecessary capabilities for a container can increase the impact of a container compromise.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0046 - NSA - Insecure capabilities",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"239",
		 "orgId":"1",
		 "policyName":"C-0054 - NSA - Cluster internal networking",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Kubernetes networking behavior allows traffic between pods in the cluster as a default behavior. Attackers who gain access to a single container may use it for network reachability to another container in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0054 - NSA - Cluster internal networking",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"240",
		 "orgId":"1",
		 "policyName":"C-0055 - NSA - Linux hardening",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"In order to reduce the attack surface, it is recommend, when it is possible, to harden your application using security services such as SELinux, AppArmor, and seccomp. Starting from Kubernetes version 22, SELinux is enabled by default.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0055 - NSA - Linux hardening",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"241",
		 "orgId":"1",
		 "policyName":"C-0057 - NSA - Privileged container",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"A privileged container is a container that has all the capabilities of the host machine, which lifts all the limitations regular containers have. Practically, this means that privileged containers can do almost every action that can be performed directly on the host. Attackers who gain access to a privileged container or have permissions to create a new privileged container ",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0057 - NSA - Privileged container",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"242",
		 "orgId":"1",
		 "policyName":"C-0058 - NSA - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0058 - NSA - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"243",
		 "orgId":"1",
		 "policyName":"C-0059 - NSA - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Security issue in ingress-nginx where a user that can create or update ingress objects can use the custom snippets feature to obtain all secrets in the cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0059 - NSA - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"244",
		 "orgId":"1",
		 "policyName":"C-0066 - NSA - Secret/etcd encryption enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"etcd is a consistent and highly-available key value store used as Kubernetes backing store for all cluster data. All object data in Kubernetes, like secrets, are stored there. This is the reason why it is important to protect the contents of etcd and use its data encryption feature.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0066 - NSA - Secret/etcd encryption enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"245",
		 "orgId":"1",
		 "policyName":"C-0067 - NSA - Audit logs enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Audit logging is an important security feature in Kubernetes, it enables the operator to track requests to the cluster. It is important to use it so the operator has a record of events happened in Kubernetes.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0067 - NSA - Audit logs enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"246",
		 "orgId":"1",
		 "policyName":"C-0068 - NSA - PSP enabled",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Pod Security Policies enable fine-grained authorization of pod creation and updates and it extends authorization beyond RBAC. It is an important to use PSP to control the creation of sensitive pods in your cluster.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0068 - NSA - PSP enabled ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"247",
		 "orgId":"1",
		 "policyName":"C-0069 - NSA - Disable anonymous access to Kubelet service",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"By default, requests to the kubelets HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of system:anonymous and a group of system:unauthenticated.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0069 - NSA - Disable anonymous access to Kubelet service ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"248",
		 "orgId":"1",
		 "policyName":"C-0070 - NSA - Enforce Kubelet client TLS authentication",
		 "category":"Cloud Security",
		 "stage":"deploy",
		 "description":"Kubelets are the node level orchestrator in Kubernetes control plane. They are publishing service port 10250 where they accept commands from API server. Operator must make sure that only API server is allowed to submit commands to Kubelet. This is done through client certificate verification, must configure Kubelet with client CA file to use for this purpose.",
		 "scheduled_policy":false,
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0070 - NSA - Enforce Kubelet client TLS authentication ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"249",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 70-85",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found between 70-85.",
		 "scheduled_policy":false,
		 "scriptId":"249",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 70-85",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"250",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 50-70",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found between 50-70.",
		 "scheduled_policy":false,
		 "scriptId":"249",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 50-70",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"251",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 30-50",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found between 30-50.",
		 "scheduled_policy":false,
		 "scriptId":"249",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 30-50",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"252",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 0-30",
		 "category":"CIS-Benchmark",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found below 30.",
		 "scheduled_policy":false,
		 "scriptId":"249",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 0-30",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"253",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 70-85",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found between 70-85.",
		 "scheduled_policy":false,
		 "scriptId":"253",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 70-85",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"254",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 50-70",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found between 50-70.",
		 "scheduled_policy":false,
		 "scriptId":"253",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 50-70",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"255",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 30-50",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found between 30-50.",
		 "scheduled_policy":false,
		 "scriptId":"253",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 30-50",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"256",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 0-30",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found below 30.",
		 "scheduled_policy":false,
		 "scriptId":"253",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 0-30",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"257",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 70-85",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found between 70-85.",
		 "scheduled_policy":false,
		 "scriptId":"257",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 70-85",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"258",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 50-70",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found between 50-70.",
		 "scheduled_policy":false,
		 "scriptId":"257",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 50-70",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"259",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 30-50",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found between 30-50.",
		 "scheduled_policy":false,
		 "scriptId":"257",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 30-50",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"260",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 0-30",
		 "category":"Compliance",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found below 30.",
		 "scheduled_policy":false,
		 "scriptId":"257",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 0-30",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"261",
		 "orgId":"1",
		 "policyName":"Auto-merge should be disabled",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Auto-merge should not be allowed in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"261",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"262",
		 "orgId":"1",
		 "policyName":"Deploy to Production should be preceeded by Judgements",
		 "category":"Deployment Config",
		 "stage":"deploy",
		 "description":"Deployments to sensitive environments should have a manual review and judgement stage in pipeline requiring someone to approve deployment.",
		 "scheduled_policy":false,
		 "scriptId":"262",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"263",
		 "orgId":"1",
		 "policyName":"Open to merge public repositories for code utilities",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Dependencies in code should be secure and protected from unauthorized code changes.",
		 "scheduled_policy":false,
		 "scriptId":"263",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"264",
		 "orgId":"1",
		 "policyName":"Approved user for build trigger",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Only approved users should be allowed to trigger builds.",
		 "scheduled_policy":false,
		 "scriptId":"264",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"265",
		 "orgId":"1",
		 "policyName":"Refrain from running pipelines originating from forked repos",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Forks of original repositories should not be able to trigger pipelines.",
		 "scheduled_policy":false,
		 "scriptId":"265",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"266",
		 "orgId":"1",
		 "policyName":"Bot user cannot merge the code",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot users must not be capable of merging any pull requests.",
		 "scheduled_policy":false,
		 "scriptId":"266",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"267",
		 "orgId":"1",
		 "policyName":"Admin access privilege should be with less than 5 percent users",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Only 5% of overall set of users must have admin access over code repository.",
		 "scheduled_policy":false,
		 "scriptId":"267",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"268",
		 "orgId":"1",
		 "policyName":"Inactive users Access restriction policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Users who have been inactive for more than 3 months must not have access to code repository.",
		 "scheduled_policy":false,
		 "scriptId":"268",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"269",
		 "orgId":"1",
		 "policyName":"Prohibited use of unspecified package versions",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Unspecified Package versions can results in fetching uncertified latest package versions. It should be mandatory to pull only specific version except for latest as artifacts and dependencies.",
		 "scheduled_policy":false,
		 "scriptId":"269",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"270",
		 "orgId":"1",
		 "policyName":"Centralized package manager settings",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Centralized package manager imposes additional checks on having only secure packages. Thus, having central package managers for code dependencies is important.",
		 "scheduled_policy":false,
		 "scriptId":"270",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"271",
		 "orgId":"1",
		 "policyName":"Artifacts should be signed",
		 "category":"Artifact Integrity",
		 "stage":"artifact",
		 "description":"Only signed artifact must be allowed for deployment.",
		 "scheduled_policy":false,
		 "scriptId":"271",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"272",
		 "orgId":"1",
		 "policyName":"Untrusted Deployment via Configuration Drift",
		 "category":"Deployment Config",
		 "stage":"deploy",
		 "description":"Pipeline configuration should be fetched only from trusted sources.",
		 "scheduled_policy":false,
		 "scriptId":"272",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"273",
		 "orgId":"1",
		 "policyName":"Continuously check for known vulnerabilities",
		 "category":"Vulnerability Analysis",
		 "stage":"artifact",
		 "description":"Continuous check for known vulnerabilities must be enabled in SSD.",
		 "scheduled_policy":false,
		 "scriptId":"273",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"274",
		 "orgId":"1",
		 "policyName":"High severity secret detection in code repository",
		 "category":"Secret Scan",
		 "stage":"source",
		 "description":"High Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"274",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"275",
		 "orgId":"1",
		 "policyName":"Critical severity secret detection in code repository",
		 "category":"Secret Scan",
		 "stage":"source",
		 "description":"Critical Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"275",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"276",
		 "orgId":"1",
		 "policyName":"Medium severity secret detection in code repository",
		 "category":"Secret Scan",
		 "stage":"source",
		 "description":"Medium Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"276",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"277",
		 "orgId":"1",
		 "policyName":"Low severity secret detection in code repository",
		 "category":"Secret Scan",
		 "stage":"source",
		 "description":"Low Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"277",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"278",
		 "orgId":"1",
		 "policyName":"High severity secret detection in containers",
		 "category":"Secret Scan",
		 "stage":"artifact",
		 "description":"High Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "scriptId":"278",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"279",
		 "orgId":"1",
		 "policyName":"Critical severity secret detection in containers",
		 "category":"Secret Scan",
		 "stage":"artifact",
		 "description":"Critical Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "scriptId":"279",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"280",
		 "orgId":"1",
		 "policyName":"Medium severity secret detection in containers",
		 "category":"Secret Scan",
		 "stage":"artifact",
		 "description":"Medium Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "scriptId":"280",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"281",
		 "orgId":"1",
		 "policyName":"Low severity secret detection in containers",
		 "category":"Secret Scan",
		 "stage":"artifact",
		 "description":"Low Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "scriptId":"281",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"282",
		 "orgId":"1",
		 "policyName":"High severity rule violation in helm",
		 "category":"Helm Scan",
		 "stage":"deploy",
		 "description":"High Severity rule violations in helm.",
		 "scheduled_policy":false,
		 "scriptId":"282",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"283",
		 "orgId":"1",
		 "policyName":"Critical severity rule violation in helm",
		 "category":"Helm Scan",
		 "stage":"deploy",
		 "description":"Critical Severity rule violations in helm.",
		 "scheduled_policy":false,
		 "scriptId":"283",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"284",
		 "orgId":"1",
		 "policyName":"Medium severity rule violation in helm",
		 "category":"Helm Scan",
		 "stage":"deploy",
		 "description":"Medium Severity rule violations in helm.",
		 "scheduled_policy":false,
		 "scriptId":"284",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"285",
		 "orgId":"1",
		 "policyName":"Low severity rule violation in helm",
		 "category":"Helm Scan",
		 "stage":"deploy",
		 "description":"Low Severity rule violations in helm.",
		 "scheduled_policy":false,
		 "scriptId":"285",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"286",
		 "orgId":"1",
		 "policyName":"Gitlab Repository Access Control Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Code Repository should not be publicly visible or modifiable.",
		 "scheduled_policy":false,
		 "scriptId":"286",
		 "variables":"",
		 "conditionName":"Repository Access Control Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"287",
		 "orgId":"1",
		 "policyName":"Gitlab Minimum Reviewers Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Pushed code should be reviewed by a minimum number of users as defined in the policy.",
		 "scheduled_policy":false,
		 "scriptId":"287",
		 "variables":"",
		 "conditionName":"Minimum Reviewers Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"288",
		 "orgId":"1",
		 "policyName":"Gitlab Branch Protection Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Repositories should have branch protection enabled requiring all code changes to be reviewed. This means disabling Push events and requiring Pull/Merge Requests to have code reviews.",
		 "scheduled_policy":false,
		 "scriptId":"288",
		 "variables":"",
		 "conditionName":"Branch Protection Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"289",
		 "orgId":"1",
		 "policyName":"Gitlab Bot User should not be a Repo Admin",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot User should not be a Repo Admin.",
		 "scheduled_policy":false,
		 "scriptId":"289",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"290",
		 "orgId":"1",
		 "policyName":"Gitlab SECURITY.md file should be present",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"SECURITY.md file should be present in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"290",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"291",
		 "orgId":"1",
		 "policyName":"Gitlab Repository 2FA Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Repositories should be protected based on 2FA authentication",
		 "scheduled_policy":false,
		 "scriptId":"291",
		 "variables":"",
		 "conditionName":"Repository 2FA Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"292",
		 "orgId":"1",
		 "policyName":"Gitlab Build Webhook SSL/TLS Policy",
		 "category":"Git Security Posture",
		 "stage":"build",
		 "description":"Webhooks should use SSL/TLS.",
		 "scheduled_policy":false,
		 "scriptId":"292",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"295",
		 "orgId":"1",
		 "policyName":"BitBucket Repository Access Control Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Code Repository should not be publicly visible or modifiable.",
		 "scheduled_policy":false,
		 "scriptId":"295",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"296",
		 "orgId":"1",
		 "policyName":"BitBucket Minimum Reviewers Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Pushed code should be reviewed by a minimum number of users:2 as defined in the policy.",
		 "scheduled_policy":false,
		 "scriptId":"296",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"297",
		 "orgId":"1",
		 "policyName":"BitBucket Branch Protection Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Repositories should have branch protection enabled requiring all code changes to be reviewed. This means disabling Push events and requiring Pull/Merge Requests to have code reviews.",
		 "scheduled_policy":false,
		 "scriptId":"297",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"298",
		 "orgId":"1",
		 "policyName":"BitBucket Branch Deletion Prevention Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"While the default branch can’t be deleted directly even if the setting is on, in general, it is best practice to prevent branches from being deleted by anyone with write access.",
		 "scheduled_policy":false,
		 "scriptId":"298",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"299",
		 "orgId":"1",
		 "policyName":"BitBucket Bot user cannot merge the code",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot users must not be capable of merging any pull requests.",
		 "scheduled_policy":false,
		 "scriptId":"299",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"300",
		 "orgId":"1",
		 "policyName":"BitBucket Bot User should not be a Repo Admin",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot User should not be a Repo Admin.",
		 "scheduled_policy":false,
		 "scriptId":"300",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"301",
		 "orgId":"1",
		 "policyName":"BitBucket Bot User should not be an Org Owner",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Bot User should not be an Org Owner.",
		 "scheduled_policy":false,
		 "scriptId":"301",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"302",
		 "orgId":"1",
		 "policyName":"BitBucket Auto-merge should be disabled",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Auto-merge should not be allowed in code repository.",
		 "scheduled_policy":false,
		 "scriptId":"302",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"303",
		 "orgId":"1",
		 "policyName":"BitBucket Single Owner of Organization",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"To reduce the attack surface it is recommended to have more than 1 admin of an organization or workspace.",
		 "scheduled_policy":false,
		 "scriptId":"303",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"304",
		 "orgId":"1",
		 "policyName":"BitBucket Admin access privilege should be with less than 5 percent users",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Only 5% of overall set of users must have admin access over code repository.",
		 "scheduled_policy":false,
		 "scriptId":"304",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"305",
		 "orgId":"1",
		 "policyName":"BitBucket Webhook Usage Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Webhook provide secure way of consuming events from source repository. Thus, webhooks must be used for integration with other platforms.",
		 "scheduled_policy":false,
		 "scriptId":"305",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"306",
		 "orgId":"1",
		 "policyName":"BitBucket Webhook SSL/TLS Protection Policy",
		 "category":"Git Security Posture",
		 "stage":"source",
		 "description":"Webhooks should use SSL/TLS.",
		 "scheduled_policy":false,
		 "scriptId":"306",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"307",
		 "orgId":"1",
		 "policyName":"Snyk Code Scan - High Severity Findings Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of high-severity findings in Snyk Code Scan analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "scriptId":"307",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"308",
		 "orgId":"1",
		 "policyName":"Snyk Code Scan - Medium Severity Findings Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of medium-severity findings in Snyk Code Scan analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "scriptId":"308",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"309",
		 "orgId":"1",
		 "policyName":"Snyk Code Scan - Low Severity Findings Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of low-severity findings in Snyk Code Scan analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "scriptId":"309",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"310",
		 "orgId":"1",
		 "policyName":"Code License Scan - License Association Policy",
		 "category":"License Scan",
		 "stage":"source",
		 "description":"This policy is designed to ensure association of appropriate licenses with source code repository.",
		 "scheduled_policy":false,
		 "scriptId":"310",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"311",
		 "orgId":"1",
		 "policyName":"Code License Scan - Low Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"source",
		 "description":"This policy is designed to restrict association of low severity licenses with source code repository.",
		 "scheduled_policy":false,
		 "scriptId":"311",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"312",
		 "orgId":"1",
		 "policyName":"Code License Scan - Medium Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"source",
		 "description":"This policy is designed to restrict association of medium or unknown severity licenses with source code repository.",
		 "scheduled_policy":false,
		 "scriptId":"312",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"313",
		 "orgId":"1",
		 "policyName":"Code License Scan - High Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"source",
		 "description":"This policy is designed to restrict association of high severity licenses with source code repository.",
		 "scheduled_policy":false,
		 "scriptId":"313",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"314",
		 "orgId":"1",
		 "policyName":"Code License Scan - Critical Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"source",
		 "description":"This policy is designed to restrict association of critical severity licenses with source code repository.",
		 "scheduled_policy":false,
		 "scriptId":"314",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"315",
		 "orgId":"1",
		 "policyName":"Artifact License Scan - License Association Policy",
		 "category":"License Scan",
		 "stage":"artifact",
		 "description":"This policy is designed to ensure association of appropriate licenses with artifact and its components.",
		 "scheduled_policy":false,
		 "scriptId":"315",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"316",
		 "orgId":"1",
		 "policyName":"Artifact License Scan - Low Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"artifact",
		 "description":"This policy is designed to restrict association of low severity licenses with artifact and its components.",
		 "scheduled_policy":false,
		 "scriptId":"316",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"317",
		 "orgId":"1",
		 "policyName":"Artifact License Scan - Medium Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"artifact",
		 "description":"This policy is designed to restrict association of medium or unknown severity licenses with artifact and its components.",
		 "scheduled_policy":false,
		 "scriptId":"317",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"318",
		 "orgId":"1",
		 "policyName":"Artifact License Scan - High Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"artifact",
		 "description":"This policy is designed to restrict association of high severity licenses with artifact and its components.",
		 "scheduled_policy":false,
		 "scriptId":"318",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"319",
		 "orgId":"1",
		 "policyName":"Artifact License Scan - Critical Severity License Association Policy",
		 "category":"License Scan",
		 "stage":"artifact",
		 "description":"This policy is designed to restrict association of critical severity licenses with artifact and its components.",
		 "scheduled_policy":false,
		 "scriptId":"319",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"320",
		 "orgId":"1",
		 "policyName":"Virus Total Scan - Malicious URL in Code or Configuration Policy",
		 "category":"Code Security",
		 "stage":"source",
		 "description":"This policy is designed to restrict usage of any malicious URL in source code repository or configuration files.",
		 "scheduled_policy":false,
		 "scriptId":"320",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"321",
		 "orgId":"1",
		 "policyName":"Virus Total Scan - Suspicious URL in Code or Configuration Policy",
		 "category":"Code Security",
		 "stage":"source",
		 "description":"This policy is designed to restrict usage of any suspicious URL in source code repository or configuration files.",
		 "scheduled_policy":false,
		 "scriptId":"321",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"322",
		 "orgId":"1",
		 "policyName":"Github Actions Secret Management Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Ensure all sensitive data is stored as secrets and not hardcoded in workflows.",
		 "scheduled_policy":false,
		 "scriptId":"322",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"323",
		 "orgId":"1",
		 "policyName":"Github Actions Approved Actions Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Only use approved GitHub Actions from a whitelist of trusted sources.",
		 "scheduled_policy":false,
		 "scriptId":"323",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"324",
		 "orgId":"1",
		 "policyName":"Github Actions Dependency Management Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Ensure dependencies are checked and managed securely. This policy verifies that dependencies are fetched from trusted sources and validate checksums where applicable.",
		 "scheduled_policy":false,
		 "scriptId":"324",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"325",
		 "orgId":"1",
		 "policyName":"Github Actions Workflow Trigger Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Ensure workflows are triggered securely to prevent abuse. This policy verifies that workflows are triggered on specific branches and events, and not on arbitrary pushes or pull requests.",
		 "scheduled_policy":false,
		 "scriptId":"325",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"326",
		 "orgId":"1",
		 "policyName":"Github Actions Secure Communication Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Ensure secure communication channels are used within workflows. This policy verifies that all network communications within workflows use secure protocols.",
		 "scheduled_policy":false,
		 "scriptId":"326",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"327",
		 "orgId":"1",
		 "policyName":"Github Actions Timeout Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Ensure workflows have appropriate timeout settings to prevent runaway processes.",
		 "scheduled_policy":false,
		 "scriptId":"327",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"328",
		 "orgId":"1",
		 "policyName":"Github Actions Workflow Permissions Policy",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Ensure workflows has limited permissions over repository.",
		 "scheduled_policy":false,
		 "scriptId":"328",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"329",
		 "orgId":"1",
		 "policyName":"Sonarqube Blocker Issues Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports various Blocker severity issues found during SAST Scans in Sonarqube.",
		 "scheduled_policy":false,
		 "scriptId":"329",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"330",
		 "orgId":"1",
		 "policyName":"Sonarqube Critical Issues Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports various Critical severity issues found during SAST Scans in Sonarqube.",
		 "scheduled_policy":false,
		 "scriptId":"330",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"331",
		 "orgId":"1",
		 "policyName":"Sonarqube Blocker/Critical Issues Status Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports number of Blocker or Critical severity issues found during SAST Scans in Sonarqube.",
		 "scheduled_policy":false,
		 "scriptId":"331",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"332",
		 "orgId":"1",
		 "policyName":"Sonarqube Major Issues Status Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports number of Major severity issues found during SAST Scans in Sonarqube.",
		 "scheduled_policy":false,
		 "scriptId":"332",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"333",
		 "orgId":"1",
		 "policyName":"Sonarqube Info/Minor Issues Status Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports number of Info or Minor severity issues found during SAST Scans in Sonarqube.",
		 "scheduled_policy":false,
		 "scriptId":"333",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"334",
		 "orgId":"1",
		 "policyName":"Codacy Critical Issues Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports number of Critical or Error severity issues found during SAST Scans in Codacy.",
		 "scheduled_policy":false,
		 "scriptId":"334",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"335",
		 "orgId":"1",
		 "policyName":"Codacy Major/Warning Issues Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports number of Major or Warning severity issues found during SAST Scans in Codacy.",
		 "scheduled_policy":false,
		 "scriptId":"335",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"336",
		 "orgId":"1",
		 "policyName":"Codacy Info Issues Policy",
		 "category":"SAST",
		 "stage":"source",
		 "description":"Reports number of Info or Minor severity issues found during SAST Scans in Codacy.",
		 "scheduled_policy":false,
		 "scriptId":"336",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"337",
		 "orgId":"1",
		 "policyName":"OWASP ZAP DAST Scan High Risk Policy",
		 "category":"DAST",
		 "stage":"postdeploy",
		 "description":"Reports High risk issues found during DAST Scans in OWASP ZAP.",
		 "scheduled_policy":false,
		 "scriptId":"337",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"338",
		 "orgId":"1",
		 "policyName":"OWASP ZAP DAST Scan Medium Risk Policy",
		 "category":"DAST",
		 "stage":"postdeploy",
		 "description":"Reports Medium risk issues found during DAST Scans in OWASP ZAP.",
		 "scheduled_policy":false,
		 "scriptId":"338",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"339",
		 "orgId":"1",
		 "policyName":"OWASP ZAP DAST Scan Low Risk Policy",
		 "category":"DAST",
		 "stage":"postdeploy",
		 "description":"Reports Low risk issues found during DAST Scans in OWASP ZAP.",
		 "scheduled_policy":false,
		 "scriptId":"339",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"340",
		 "orgId":"1",
		 "policyName":"OWASP ZAP DAST Scan Informational Risk Policy",
		 "category":"DAST",
		 "stage":"postdeploy",
		 "description":"Reports Informational risk issues found during DAST Scans in OWASP ZAP.",
		 "scheduled_policy":false,
		 "scriptId":"340",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"341",
		 "orgId":"1",
		 "policyName":"Low Vulnerability Prevention Policy for Jenkins Plugins",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Low Severity Vulnerability should not be found in the plugins installed on the Jenkins Servers.",
		 "scheduled_policy":false,
		 "scriptId":"341",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"342",
		 "orgId":"1",
		 "policyName":"Critical Vulnerability Prevention Policy for Jenkins Plugins",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Critical Severity Vulnerabilities should not be found in the plugins installed on the Jenkins Servers.",
		 "scheduled_policy":false,
		 "scriptId":"342",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"343",
		 "orgId":"1",
		 "policyName":"Medium Vulnerability Prevention Policy for Jenkins Plugins",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"Medium Severity Vulnerabilities should not be found in the plugins installed on the Jenkins Servers.",
		 "scheduled_policy":false,
		 "scriptId":"343",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"344",
		 "orgId":"1",
		 "policyName":"High Vulnerability Prevention Policy for Jenkins Plugins",
		 "category":"Build Security Posture",
		 "stage":"build",
		 "description":"High Severity Vulnerabilities should not be found in the plugins installed on the Jenkins Servers.",
		 "scheduled_policy":false,
		 "scriptId":"344",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
       {
                "policyId":"345",
                "orgId":"1",
                "policyName":"AWS:EC2:unused-security-group",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Unused Security Group",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"346",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-whitelists-aws",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Whitelists AWS CIDRs",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"347",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-UDP-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens UDP Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"348",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-TCP-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens TCP Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"349",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-SSH-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens SSH Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"350",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-SMTP-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens SMTP Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"351",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-RDP-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens RDP Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"352",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-PostgreSQL-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens PostgreSQL Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"353",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-port-range",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Uses Port Range",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"354",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-plaintext-port-Telnet",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens Telnet Port",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"355",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-plaintext-port-FTP",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens FTP Port",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"356",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-oracle-db-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens Oracle DB Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"357",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-NFS-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens NFS Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"358",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-MySQL-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens MySQL Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"359",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-MsSQL-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens MsSQL Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"360",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-MongoDB-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens MongoDB Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"361",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-icmp-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Allows ICMP Traffic to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"362",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-DNS-port-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens DNS Port to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"363",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-all-ports-to-self",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Unrestricted Network Traffic within Security Group",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"364",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-all-ports-to-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens All Ports to All",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"365",
                "orgId":"1",
                "policyName":"AWS:EC2:security-group-opens-all-ports",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Security Group Opens All Ports",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"366",
                "orgId":"1",
                "policyName":"AWS:EC2:instance-with-user-data-secrets",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Potential Secret in Instance User Data",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"367",
                "orgId":"1",
                "policyName":"AWS:EC2:ebs-volume-not-encrypted",
                "category":"CSPM",
                "stage":"deploy",
                "description":"EBS Volume Not Encrypted",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"368",
                "orgId":"1",
                "policyName":"AWS:EC2:ebs-snapshot-public",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Public EBS Snapshot",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"369",
                "orgId":"1",
                "policyName":"AWS:EC2:ebs-snapshot-not-encrypted",
                "category":"CSPM",
                "stage":"deploy",
                "description":"EBS Snapshot Not Encrypted",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"370",
                "orgId":"1",
                "policyName":"AWS:EC2:ebs-default-encryption-disabled",
                "category":"CSPM",
                "stage":"deploy",
                "description":"EBS Encryption By Default Is Disabled",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"371",
                "orgId":"1",
                "policyName":"AWS:EC2:default-security-group-with-rules",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Non-empty Rulesets for Default Security Groups",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"372",
                "orgId":"1",
                "policyName":"AWS:EC2:default-security-group-in-use",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Default Security Groups in Use",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"373",
                "orgId":"1",
                "policyName":"AWS:EC2:ami-public",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Publicly Accessible AMI",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"374",
                "orgId":"1",
                "policyName":"AWS:VPC:custom-network-acls-allow-all-egress",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Network ACLs Allow All egress Traffic (custom)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"375",
                "orgId":"1",
                "policyName":"AWS:VPC:custom-network-acls-allow-all-ingress",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Network ACLs Allow All ingress Traffic (custom)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"376",
                "orgId":"1",
                "policyName":"AWS:VPC:default-network-acls-allow-all-egress",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Network ACLs Allow All egress Traffic (default)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"377",
                "orgId":"1",
                "policyName":"AWS:VPC:default-network-acls-allow-all-ingress",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Network ACLs Allow All ingress Traffic (default)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"378",
                "orgId":"1",
                "policyName":"AWS:VPC:network-acl-not-used",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Unused Network ACLs",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"379",
                "orgId":"1",
                "policyName":"AWS:VPC:routing-tables-with-peering",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Routing Table with VPC Peering",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"380",
                "orgId":"1",
                "policyName":"AWS:VPC:subnet-with-allow-all-egress-acls",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Subnet with Allow All egress NACLs",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"381",
                "orgId":"1",
                "policyName":"AWS:VPC:subnet-with-allow-all-ingress-acls",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Subnet with Allow All ingress NACLs",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"382",
                "orgId":"1",
                "policyName":"AWS:VPC:subnet-without-flow-log",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Subnet without a Flow Log",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"383",
                "orgId":"1",
                "policyName":"Virus Total Malicious Malware Detection Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"Virus Total detects various Malwares that can be attached to an APK or IPA file which can harm hosting device or compromise user data upon installation.",
                "scheduled_policy":false,
                "scriptId":"383",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"384",
                "orgId":"1",
                "policyName":"Virus Total Suspicious Malware Detection Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"Virus Total detects various Malwares that can be attached to an APK or IPA file which can harm hosting device or compromise user data upon installation.",
                "scheduled_policy":false,
                "scriptId":"384",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"385",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Certificate Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the authenticity of attached certificates and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"385",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"386",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Certificate Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the authenticity of attached certificates and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"386",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"387",
                "orgId":"1",
                "policyName":"MobSF: High Severity Certificate Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the authenticity of attached certificates and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"387",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"388",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Permissions Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the permissions assigned to an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"388",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"389",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Permissions Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the permissions assigned to an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"389",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"390",
                "orgId":"1",
                "policyName":"MobSF: High Severity Permissions Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the permissions assigned to an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"390",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"391",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Manifest Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the manifest of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"391",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"392",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Manifest Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the manifest of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"392",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"393",
                "orgId":"1",
                "policyName":"MobSF: High Severity Manifest Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the manifest of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"393",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"394",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Network Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the network configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"394",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"395",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Network Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the network configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"395",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"396",
                "orgId":"1",
                "policyName":"MobSF: High Severity Network Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the network configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"396",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"397",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Binary Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the binary configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"397",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"398",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Binary Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the binary configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"398",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"399",
                "orgId":"1",
                "policyName":"MobSF: High Severity Binary Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the binary configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"399",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"400",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Mach-O Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the Mach-O configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"400",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"401",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Mach-O Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the Mach-O configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"401",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"402",
                "orgId":"1",
                "policyName":"MobSF: High Severity Mach-O Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan checks the Mach-O configuration of an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"402",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"403",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Code Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs Code Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"403",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"404",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Code Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs Code Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"404",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"405",
                "orgId":"1",
                "policyName":"MobSF: High Severity Code Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs Code Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"405",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"406",
                "orgId":"1",
                "policyName":"MobSF: Low Severity AppSec Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs AppSec Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"406",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"407",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity AppSec Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs AppSec Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"407",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"408",
                "orgId":"1",
                "policyName":"MobSF: High Severity AppSec Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs AppSec Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"408",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"409",
                "orgId":"1",
                "policyName":"MobSF: Low Severity Android API Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs Android API Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"409",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"410",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity Android API Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs Android API Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"410",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"411",
                "orgId":"1",
                "policyName":"MobSF: High Severity Android API Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs Android API Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"411",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"412",
                "orgId":"1",
                "policyName":"MobSF: Low Severity IOS API Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs IOS API Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"412",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"413",
                "orgId":"1",
                "policyName":"MobSF: Medium Severity IOS API Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs IOS API Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"413",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"414",
                "orgId":"1",
                "policyName":"MobSF: High Severity IOS API Issues Policy",
                "category":"Mobile Application Security Posture",
                "stage":"artifact",
                "description":"MobSF Static Scan performs IOS API Analysis on an application and raises issues in case of rule violations.",
                "scheduled_policy":false,
                "scriptId":"414",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"415",
                "orgId":"1",
                "policyName":"TfSec: IaC Scan Low Severity Issues Policy",
                "category":"IaC Security Posture",
                "stage":"deploy",
                "description":"TfSec Scan checks for security violations in terraform scripts.",
                "scheduled_policy":false,
                "scriptId":"415",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"416",
                "orgId":"1",
                "policyName":"TfSec: IaC Scan Medium Severity Issues Policy",
                "category":"IaC Security Posture",
                "stage":"deploy",
                "description":"TfSec Scan checks for security violations in terraform scripts.",
                "scheduled_policy":false,
                "scriptId":"416",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
	   {
                "policyId":"417",
                "orgId":"1",
                "policyName":"TfSec: IaC Scan High Severity Issues Policy",
                "category":"IaC Security Posture",
                "stage":"deploy",
                "description":"TfSec Scan checks for security violations in terraform scripts.",
                "scheduled_policy":false,
                "scriptId":"417",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"418",
                "orgId":"1",
                "policyName":"AWS:IAM:user-with-password-and-key",
                "category":"CSPM",
                "stage":"deploy",
                "description":"User with Password and Keys Enabled",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"419",
                "orgId":"1",
                "policyName":"AWS:IAM:user-without-mfa",
                "category":"CSPM",
                "stage":"deploy",
                "description":"User without MFA",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"420",
                "orgId":"1",
                "policyName":"AWS:IAM:user-with-multiple-access-keys",
                "category":"CSPM",
                "stage":"deploy",
                "description":"User with Multiple API Keys",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"421",
                "orgId":"1",
                "policyName":"AWS:IAM:user-with-inline-policies",
                "category":"CSPM",
                "stage":"deploy",
                "description":"User with inline Policies",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"422",
                "orgId":"1",
                "policyName":"AWS:IAM:user-no-inactive-key-rotation",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Lack of Key Rotation for 90 Days (Key Status: Inactive)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"423",
                "orgId":"1",
                "policyName":"AWS:IAM:user-no-Active-key-rotation",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Lack of Key Rotation for 90 Days (Key Status: Active)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"424",
                "orgId":"1",
                "policyName":"AWS:IAM:unused-credentials-not-disabled",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Credentials Unused for 90 Days or Greater Are Not Disabled",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"425",
                "orgId":"1",
                "policyName":"AWS:IAM:root-account-with-active-keys",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Root Account Has Active Keys",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"426",
                "orgId":"1",
                "policyName":"AWS:IAM:root-account-with-active-certs",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Root Account Has Active X.509 Certs",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"427",
                "orgId":"1",
                "policyName":"AWS:IAM:root-account-used-recently",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Root Account Used Recently",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"428",
                "orgId":"1",
                "policyName":"AWS:IAM:root-account-no-mfa",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Root Account without MFA",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"429",
                "orgId":"1",
                "policyName":"AWS:IAM:root-account-no-hardware-mfa",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Root Account without Hardware MFA",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"430",
                "orgId":"1",
                "policyName":"AWS:IAM:role-with-inline-policies",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Role with Inline Policies",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"431",
                "orgId":"1",
                "policyName":"AWS:IAM:password-policy-reuse-enabled",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Password Policy Allows the Reuse of Passwords",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"432",
                "orgId":"1",
                "policyName":"AWS:IAM:password-policy-no-expiration",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Password Expiration Disabled",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"433",
                "orgId":"1",
                "policyName":"AWS:IAM:password-policy-minimum-length",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Minimum Password Length Too Short",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"434",
                "orgId":"1",
                "policyName":"AWS:IAM:password-policy-expiration-threshold",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Passwords Expire after 90 Days",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"435",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-no-attachments",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Not Attached to Any Entity",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"436",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"437",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"438",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"439",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-full-privileges",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows All Actions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"440",
                "orgId":"1",
                "policyName":"AWS:IAM:lightspin-user-action-denied-for-group",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Policy with Denied User Actions for Group Objects",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"441",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-user-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline user Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"442",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-user-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline user Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"443",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-user-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline user Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"444",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-role-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline role Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"445",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-role-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline role Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"446",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-role-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline role Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"447",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-group-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline group Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"448",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-group-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline group Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"449",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-group-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline group Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"450",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-group-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline group Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"451",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-group-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline group Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"452",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-group-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline group Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"453",
                "orgId":"1",
                "policyName":"AWS:IAM:group-with-no-users",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Group with No Users",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"454",
                "orgId":"1",
                "policyName":"AWS:IAM:group-with-inline-policies",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Group with Inline Policies",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"455",
                "orgId":"1",
                "policyName":"AWS:IAM:ec2-role-without-instances",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Unused Role for EC2 Service",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"456",
                "orgId":"1",
                "policyName":"AWS:IAM:assume-role-policy-allows-all",
                "category":"CSPM",
                "stage":"deploy",
                "description":"AssumeRole Policy Allows All Principals",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"457",
                "orgId":"1",
                "policyName":"AWS:IAM:assume-role-lacks-external-id-and-mfa",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Cross-Account AssumeRole Policy Lacks External ID and MFA",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"458",
                "orgId":"1",
                "policyName":"AWS:IAM:user-no-Inactive-key-rotation",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Lack of Key Rotation for 90 Days (Key Status: Inactive)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"459",
                "orgId":"1",
                "policyName":"AWS:IAM:user-no-Active-key-rotation",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Lack of Key Rotation for 90 Days (Key Status: Active)",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"460",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"461",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"462",
                "orgId":"1",
                "policyName":"AWS:IAM:managed-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Managed Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"463",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-user-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline user Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"464",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-user-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline user Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"465",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-user-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline user Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"466",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-role-policy-allows-sts-AssumeRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline role Policy Allows sts:AssumeRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"467",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-role-policy-allows-NotActions",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline role Policy Allows NotActions",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
	`
       {
                "policyId":"468",
                "orgId":"1",
                "policyName":"AWS:IAM:inline-role-policy-allows-iam-PassRole",
                "category":"CSPM",
                "stage":"deploy",
                "description":"Inline role Policy Allows iam:PassRole For All Resources",
                "scheduled_policy":false,
                "scriptId":"345",
                "variables":"",
                "conditionName":"",
                "suggestion":""
       }
       `,
}

var policyEnforcement = []string{
	`{
      "policyId": "1",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1"
      ]
  }`,
	`{
      "policyId": "2",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "2",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1"
      ]
  }`,
	`{
      "policyId": "3",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "true",
      "status": true, 
	  "datasourceTool": "github",
      "tags": [
         "1",
         "11",
         "13",
		 "17"
      ]
  }`,
	`{
      "policyId": "4",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
		"1",
		"11",
		"13",
		"17"
      ]
  }`,
	`{
      "policyId": "5",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1"
      ]
  }`,
	`{
      "policyId": "6",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1"
      ]
  }`,
	`{
      "policyId": "7",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "LOW",
      "status": true,
	  "forceApply":true,
	  "datasourceTool": "graphql",
      "tags": [
         "17",
         "22"
      ]
  }`,
	`{
      "policyId": "8",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "CRITICAL",
      "status": true,
	  "forceApply":true,
	  "datasourceTool": "graphql",
      "tags": [
		"17",
		"22"
      ]
  }`,
	`{
      "policyId": "9",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "MEDIUM",
      "status": true,
	  "forceApply":true,
	  "datasourceTool": "graphql",
      "tags": [
		"17",
		"22"
      ]
  }`,
	`{
      "policyId": "10",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "11",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "12",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "jenkins",
      "tags": [
         "2"
      ]
  }`,
	`{
      "policyId": "13",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4",
         "11",
         "13",
         "17"
      ]
  }`,
	`{
      "policyId": "14",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "15",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "16",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "17",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "18",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "19",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "20",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "21",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "22",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "23",
      "severity": "Medium",
      "action": "Alert",
	  "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "24",
      "severity": "Medium",
      "action": "Alert",
	  "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "25",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "26",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "27",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "28",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "29",
      "severity": "Critical",
      "action": "Alert",
	  "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4",
         "17"
      ]
  }`,
	`{
      "policyId": "30",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "31",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "4"
      ]
  }`,
	`{
      "policyId": "32",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1"
      ]
  }`,
	`{
      "policyId": "33",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1",
         "11",
         "13",
         "17"
      ]
  }`,
	`{
      "policyId": "34",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
        "1",
         "11",
         "13",
         "17"
      ]
  }`,
	`{
      "policyId": "35",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "36",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "37",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "jenkins",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "38",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "docker",
      "tags": [
         "2"
      ]
  }`,
	`{
	"policyId": "38",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "quay",
	"tags": [
	   "2"
	]
  }`,
	`{
	"policyId": "38",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "jfrog",
	"tags": [
	   "2"
	]
  }`,
	`{
	"policyId": "38",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "ecr",
	"tags": [
	   "2"
	]
  }`,
	`{
	"policyId": "38",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "acr",
	"tags": [
	   "2"
	]
	}`,
	`{
	"policyId": "38",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "gcr",
	"tags": [
	   "2"
	]
	}`,
	`{
      "policyId": "39",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "docker",
      "tags": [
         "2"
      ]
  }`,
	`{
	"policyId": "39",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "quay",
	"tags": [
	   "2"
	]
  }`,
	`{
	"policyId": "39",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "jfrog",
	"tags": [
	   "2"
	]
  }`,
	`{
	"policyId": "39",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "ecr",
	"tags": [
	   "2"
	]
  }`,
	`{
	"policyId": "39",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "acr",
	"tags": [
	   "2"
	]
	}`,
	`{
	"policyId": "39",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "gcr",
	"tags": [
	   "2"
	]
	}`,
	`{
      "policyId": "40",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "1"
      ]
  }`,
	`{
      "policyId": "41",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "docker",
      "tags": [
         "2"
      ]
  }`,
	`{
      "policyId": "42",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "5",
      "status": true,
	  "datasourceTool": "openssf",
      "tags": [
         "17",
         "4"
      ]
  }`,
	`{
      "policyId": "43",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "2.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
         "12",
         "11",
		 "10"
      ]
  }`,
	`{
      "policyId": "44",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "3.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "45",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "4.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "46",
      "severity": "Medium",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "5",
         "7",
         "8",
         "17"
      ]
  }`,
	`{
      "policyId": "47",
      "severity": "Medium",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
		"5",
		"7",
		"8",
		"17"
      ]
  }`,
	`{
      "policyId": "48",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "semgrep",
      "tags": [
		"12",
         "11",
		 "10"
      ]
  }`,
	`{
      "policyId": "49",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "semgrep",
      "tags": [
		 "12",
         "11",
		 "10"
      ]
  }`,
	`{
      "policyId": "50",
      "severity": "Low",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
		"5",
		"7",
		"8",
		"17"
      ]
  }`,
	`{
      "policyId": "51",
      "severity": "Medium",
      "action": "Alert",
      "status": false,
	  "datasourceTool": "sonarqube",
      "tags": [
		"10",
		"7",
		"8",
		"17"
      ]
  }`,
	`{
	"policyId": "51",
	"severity": "Medium",
	"action": "Alert",
	"status": false,
	"datasourceTool": "semgrep",
	"tags": [
		"5",
		"7",
		"8",
		"17"
	]
  }`,
	`{
      "policyId": "52",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "semgrep",
      "tags": [
		 "12",
         "11",
		 "10"
      ]
  }`,
	`{
      "policyId": "53",
      "severity": "High",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "54",
      "severity": "High",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "55",
      "severity": "High",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "56",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "57",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "58",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "59",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "60",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "61",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "62",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "63",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "64",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "65",
      "severity": "Critical",
      "action": "Prevent",
      "status": false,
	  "datasourceTool": "kubernetes",
      "tags": [
         "6"
      ]
  }`,
	`{
      "policyId": "66",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "67",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "5.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "68",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "2.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "69",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "3.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "70",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "4.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "71",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "1.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "72",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "2.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "73",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "3.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "74",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "4.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "75",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "1.0",
      "status": true,
	  "datasourceTool": "sonarqube",
      "tags": [
		"12",
		"11",
		"10"
      ]
  }`,
	`{
      "policyId": "76",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "forceApply":true,
	  "datasourceTool": "graphql",
      "tags": [
         "17",
         "22"
      ]
  }`,
	`{
      "policyId": "77",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "78",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "79",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "80",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "81",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "82",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "83",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "84",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "85",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "86",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "87",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "88",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "89",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "90",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "91",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "92",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "93",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "94",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "95",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "96",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "97",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "98",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "99",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "100",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "101",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "102",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "103",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "104",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "105",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "106",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "107",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "108",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "109",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "110",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "111",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "112",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "113",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "114",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "115",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "116",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "117",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "118",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "119",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "120",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "121",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "122",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "123",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "124",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "125",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "126",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "127",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "128",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "129",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "130",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "131",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "132",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "133",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "134",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "135",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "136",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "137",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "138",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "139",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "140",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "141",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "142",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "143",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "144",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "145",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "146",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "147",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "148",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "149",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "150",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "151",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "152",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "153",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "154",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "155",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "156",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "157",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "158",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "159",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "160",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "161",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "162",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "163",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "164",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "165",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "166",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "167",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "168",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "169",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "170",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "171",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "172",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "173",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "174",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "175",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "176",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "177",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "178",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "179",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "180",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "181",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "182",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "183",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "184",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "185",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "186",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "187",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "188",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "189",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "190",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "191",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "192",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "193",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "194",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "195",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "196",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "197",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "198",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
         "17",
		"27"
      ]
  }`,
	`{
      "policyId": "199",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
         "17",
		"27"
      ]
  }`,
	`{
      "policyId": "200",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
         "17",
		"27"
      ]
  }`,
	`{
      "policyId": "201",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
         "17",
		"27"
      ]
  }`,
	`{
      "policyId": "202",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
         "17",
		"27"
      ]
  }`,
	`{
      "policyId": "203",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
         "17",
		"27"
      ]
  }`,
	`{
      "policyId": "204",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "205",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "206",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "207",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "208",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "209",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
        "15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "210",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "211",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "212",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "213",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "214",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "215",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "216",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "217",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"27"
      ]
  }`,
	`{
      "policyId": "218",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "219",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "220",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "221",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "222",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "223",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "224",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
        "17",
		"27"
      ]
  }`,
	`{
      "policyId": "225",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "226",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "227",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "228",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "229",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "230",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "231",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "232",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "233",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "234",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "235",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "236",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "237",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "238",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "239",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "240",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "241",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "242",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "243",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "244",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "245",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "246",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "247",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "248",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "27"
      ]
  }`,
	`{
      "policyId": "249",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "70-85",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "250",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "50-70",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "251",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "30-50",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "252",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "0-30",
      "status": true,
	  "datasourceTool": "cis-kubescape",
      "tags": [
         "14"
      ]
  }`,
	`{
      "policyId": "253",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "70-85",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
         "15",
		 "17",
		 "28"
      ]
  }`,
	`{
      "policyId": "254",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "50-70",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"28"
      ]
  }`,
	`{
      "policyId": "255",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "30-50",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"28"
      ]
  }`,
	`{
      "policyId": "256",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "0-30",
      "status": true,
	  "datasourceTool": "mitre-kubescape",
      "tags": [
		"15",
		"17",
		"28"
      ]
  }`,
	`{
      "policyId": "257",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "70-85",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "28"
      ]
  }`,
	`{
      "policyId": "258",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "50-70",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "28"
      ]
  }`,
	`{
      "policyId": "259",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "30-50",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "28"
      ]
  }`,
	`{
      "policyId": "260",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "0-30",
      "status": true,
	  "datasourceTool": "nsa-kubescape",
      "tags": [
         "16",
		 "28"
      ]
  }`,
	`{
      "policyId": "261",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "262",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "spinnaker",
      "tags": [
         "18",
		 "5"
      ]
  }`,
	`{
      "policyId": "263",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "264",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "jenkins",
      "tags": [
         "18",
		 "3"
      ]
  }`,
	`{
      "policyId": "265",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "266",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "267",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "268",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "269",
      "status": true,
	  "action": "Alert",
	  "severity": "Medium",
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "270",
      "status": true,
	  "action": "Alert",
	  "severity": "Medium",
	  "datasourceTool": "github",
      "tags": [
         "18",
		 "1"
      ]
  }`,
	`{
      "policyId": "271",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "docker",
      "tags": [
         "18",
		 "2"
      ]
  }`,
	`{
	"policyId": "271",
	"severity": "Medium",
	"action": "Alert",
	"status": true,
	"datasourceTool": "jfrog",
	"tags": [
	   "18",
	   "2"
	]
  }`,
	`{
	"policyId": "271",
	"severity": "Medium",
	"action": "Alert",
	"status": true,
	"datasourceTool": "quay",
	"tags": [
	   "18",
	   "2"
	]
  }`,
	`{
	"policyId": "271",
	"severity": "Medium",
	"action": "Alert",
	"status": true,
	"datasourceTool": "ecr",
	"tags": [
	   "18",
	   "2"
	]
  }`,
	`{
	"policyId": "271",
	"severity": "Medium",
	"action": "Alert",
	"status": true,
	"datasourceTool": "acr",
	"tags": [
	   "18",
	   "2"
	]
  }`,
	`{
	"policyId": "271",
	"severity": "Medium",
	"action": "Alert",
	"status": true,
	"datasourceTool": "gcr",
	"tags": [
	   "18",
	   "2"
	]
  }`,
	`{
      "policyId": "272",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "kubernetes",
      "tags": [
         "18",
		 "5"
      ]
  }`,
	`{
      "policyId": "273",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "docker",
      "tags": [
         "18",
		 "22"
      ]
  }`,
	`{
	"policyId": "273",
	"severity": "Critical",
	"action": "Alert",
	"status": true,
	"datasourceTool": "quay",
	"tags": [
	   "18",
	   "22"
	]
  }`,
	`{
	"policyId": "273",
	"severity": "Critical",
	"action": "Alert",
	"status": true,
	"datasourceTool": "jfrog",
	"tags": [
	   "18",
	   "22"
	]
  }`,
	`{
	"policyId": "273",
	"severity": "Critical",
	"action": "Alert",
	"status": true,
	"datasourceTool": "ecr",
	"tags": [
	   "18",
	   "22"
	]
  }`,
	`{
	"policyId": "273",
	"severity": "Critical",
	"action": "Alert",
	"status": true,
	"datasourceTool": "acr",
	"tags": [
	   "18",
	   "22"
	]
   }`,
	`{
	"policyId": "273",
	"severity": "Critical",
	"action": "Alert",
	"status": true,
	"datasourceTool": "gcr",
	"tags": [
	   "18",
	   "22"
	]
   }`,
	`{
      "policyId": "274",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "19"
      ]
  }`,
	`{
      "policyId": "275",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "19"
      ]
  }`,
	`{
      "policyId": "276",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "19"
      ]
  }`,
	`{
      "policyId": "277",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "19"
      ]
  }`,
	`{
      "policyId": "278",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "20",
		 "19"
      ]
  }`,
	`{
      "policyId": "279",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "20",
		 "19"
      ]
  }`,
	`{
      "policyId": "280",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "20",
		 "19"
      ]
  }`,
	`{
      "policyId": "281",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "20",
		 "19"
      ]
  }`,
	`{
      "policyId": "282",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "snyk",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "282",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "kubescape",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "282",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "283",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "snyk",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "283",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "kubescape",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "283",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "284",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "snyk",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "284",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "kubescape",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "284",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "285",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "snyk",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "285",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "kubescape",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "285",
      "severity": "Low",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "trivy",
      "tags": [
         "21"
      ]
  }`,
	`{
      "policyId": "286",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "287",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "288",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "289",
      "severity": "Critical",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "290",
      "severity": "High",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "291",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "true",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "292",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "gitlab",
      "tags": [
         "23",
		 "1"
      ]
  }`,
	`{
      "policyId": "262",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "argocd",
      "tags": [
         "17",
		 "5"
      ]
   }`,
	`{
      "policyId": "262",
      "severity": "Medium",
      "action": "Alert",
      "status": true,
	  "datasourceTool": "jenkins",
      "tags": [
         "17",
		 "5"
      ]
   }`,
	`{
	"policyId": "295",
	"severity": "High",
	"action": "Alert",
	"status": true,
	"datasourceTool": "bitbucket",
	"tags": [
           "24",
		   "1"
      ]
  }`,
	`{
		"policyId": "296",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
  }`,
	`{
		"policyId": "297",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
  }`,
	`{
		"policyId": "298",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
  }`,
	`{
		"policyId": "299",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
  }`,
	`{
		"policyId": "300",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "301",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "302",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "303",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "304",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "305",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "306",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "bitbucket",
		"tags": [
		   "24",
		   "1"
		]
	 }`,
	`{
		"policyId": "307",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "snyk",
		"tags": [
		   "10"
		]
	 }`,
	`{
		"policyId": "308",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "snyk",
		"tags": [
		   "10"
		]
	 }`,
	`{
		"policyId": "309",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "snyk",
		"tags": [
		   "10"
		]
	 }`,
	`{
		"policyId": "310",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "311",
		"severity": "Low",
		"action": "Alert",
		"status": false,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "312",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "313",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "314",
		"severity": "Critical",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "315",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "316",
		"severity": "Low",
		"action": "Alert",
		"status": false,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "317",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "318",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "319",
		"severity": "Critical",
		"action": "Alert",
		"status": true,
		"datasourceTool": "trivy",
		"tags": [
		   "25"
		]
	 }`,
	`{
		"policyId": "320",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "virustotal",
		"tags": [
		   "12",
		   "26"
		]
	 }`,
	`{
		"policyId": "321",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "virustotal",
		"tags": [
		   "12",
		   "26"
		]
	 }`,
	`{
		"policyId": "322",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "323",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "324",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "325",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "326",
		"severity": "High",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "327",
		"severity": "Low",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "328",
		"severity": "Medium",
		"action": "Alert",
		"status": true,
		"datasourceTool": "githubactions",
		"tags": [
		   "3",
		   "29"
		]
	 }`,
	`{
		"policyId": "329",
		"severity": "Critical",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "sonarqube",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "330",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "sonarqube",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "331",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "sonarqube",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "332",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "sonarqube",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "333",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "sonarqube",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "334",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "codacy",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "335",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "codacy",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "336",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": false,
		"datasourceTool": "codacy",
		"tags": [
		  "12",
		  "11",
		  "10"
		]
	}`,
	`{
		"policyId": "337",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "zap",
		"tags": [
		  "30"
		]
	}`,
	`{
		"policyId": "338",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "zap",
		"tags": [
		  "30"
		]
	}`,
	`{
		"policyId": "339",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "zap",
		"tags": [
		  "30"
		]
	}`,
	`{
		"policyId": "340",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "4.0",
		"status": true,
		"datasourceTool": "zap",
		"tags": [
		  "30"
		]
	}`,
	`{
      "policyId": "341",
      "severity": "Low",
      "action": "Alert",
      "conditionValue": "LOW",
      "status": true,
	  "datasourceTool": "graphql",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "342",
      "severity": "Critical",
      "action": "Alert",
      "conditionValue": "CRITICAL",
      "status": true,
	  "datasourceTool": "graphql",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "343",
      "severity": "Medium",
      "action": "Alert",
      "conditionValue": "MEDIUM",
      "status": true,
	  "datasourceTool": "graphql",
      "tags": [
         "3"
      ]
  }`,
	`{
      "policyId": "344",
      "severity": "High",
      "action": "Alert",
      "conditionValue": "HIGH",
      "status": true,
	  "datasourceTool": "graphql",
      "tags": [
         "3"
      ]
	}`,
	`{
		"policyId": "345",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "346",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "347",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "348",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "349",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "350",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "351",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "352",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "353",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "354",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "355",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "356",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "357",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "358",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "359",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "360",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "361",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "362",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "363",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "364",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "365",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "366",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "367",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "368",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "369",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "370",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "371",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "372",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "373",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "374",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "375",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "376",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "377",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "378",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "379",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "380",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "381",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "382",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "383",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "virustotal",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "384",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "virustotal",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "385",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "386",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "387",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "388",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "389",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "390",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "391",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "392",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "393",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "394",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "395",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "396",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "397",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "398",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "399",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "400",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "401",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "402",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "403",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "404",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "405",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "406",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "407",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "408",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "409",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "410",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "411",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "412",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "413",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "414",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "mobsf",
		"tags": [
			"32"
		]
	}`,
	`{
		"policyId": "415",
		"severity": "Low",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "tfsec",
		"tags": [
			"33"
		]
	}`,
	`{
		"policyId": "416",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "tfsec",
		"tags": [
			"33"
		]
	}`,
	`{
		"policyId": "417",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "tfsec",
		"tags": [
			"33"
		]
	}`,
	`{
		"policyId": "418",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "419",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "420",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "421",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "422",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "423",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "424",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "425",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "426",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "427",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "428",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "429",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "430",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "431",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "432",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "433",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "434",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "435",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "436",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "437",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "438",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "439",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "440",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "441",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "442",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "443",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "444",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "445",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "446",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "447",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "448",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "449",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "450",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "451",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "452",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "453",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "454",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "455",
		"severity": "Medium",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "456",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "457",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "458",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "459",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "460",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "461",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "462",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "463",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "464",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "465",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "466",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "467",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
	`{
		"policyId": "468",
		"severity": "High",
		"action": "Alert",
		"conditionValue": "",
		"status": true,
		"dataSourceTool": "scoutsuite",
		"tags": [
			"31"
		]
	}`,
}

var tagPolicy = []string{
	`{
		"id": "00",
		"tagName": "userdefined",
		"tagValue": "User Defined Policies",
		"tagDescription": "",
		"createdBy": "system"
	}`,
	`{
		"id": "1",
		"tagName": "policyCategory",
		"tagValue": "Git Security Posture",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "2",
		"tagName": "policyCategory",
		"tagValue": "Artifact Integrity",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "3",
		"tagName": "policyCategory",
		"tagValue": "Build Security Posture",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "4",
		"tagName": "policyCategory",
		"tagValue": "OpenSSF Scorecard",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "5",
		"tagName": "policyCategory",
		"tagValue": "Deployment Config",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "6",
		"tagName": "policyCategory",
		"tagValue": "Pod Security",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "7",
		"tagName": "policyCategory",
		"tagValue": "NIST-800-53-CM7",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "8",
		"tagName": "policyCategory",
		"tagValue": "FedRAMP-CM7",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "9",
		"tagName": "policyCategory",
		"tagValue": "FedRAMP-RA5",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "10",
		"tagName": "policyCategory",
		"tagValue": "SAST",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "11",
		"tagName": "policyCategory",
		"tagValue": "NIST-800-53-AC6",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "12",
		"tagName": "policyCategory",
		"tagValue": "Code Security",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "13",
		"tagName": "policyCategory",
		"tagValue": "FedRAMP-AC6",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "14",
		"tagName": "policyCategory",
		"tagValue": "CIS-Benchmark",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "15",
		"tagName": "policyCategory",
		"tagValue": "MITRE-ATT&CK",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "16",
		"tagName": "policyCategory",
		"tagValue": "NSA-CISA",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "17",
		"tagName": "policyCategory",
		"tagValue": "NIST-800-53-R5",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "18",
		"tagName": "policyCategory",
		"tagValue": "OWASP-CICD-Top10",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "19",
		"tagName": "policyCategory",
		"tagValue": "Secret Scan",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "20",
		"tagName": "policyCategory",
		"tagValue": "Artifact Scan",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "21",
		"tagName": "policyCategory",
		"tagValue": "Helm Scan",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "22",
		"tagName": "policyCategory",
		"tagValue": "Vulnerability Analysis",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "23",
		"tagName": "policyCategory",
		"tagValue": "Gitlab",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "24",
		"tagName": "policyCategory",
		"tagValue": "Bitbucket",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "25",
		"tagName": "policyCategory",
		"tagValue": "License Scan",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "26",
		"tagName": "policyCategory",
		"tagValue": "Virus Total Scan",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "27",
		"tagName": "policyCategory",
		"tagValue": "Cloud Security",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "28",
		"tagName": "policyCategory",
		"tagValue": "Compliance",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "29",
		"tagName": "policyCategory",
		"tagValue": "Github Actions",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "30",
		"tagName": "policyCategory",
		"tagValue": "DAST",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "31",
		"tagName": "policyCategory",
		"tagValue": "CSPM",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "32",
		"tagName": "policyCategory",
		"tagValue": "Mobile Application Security Posture",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
	`
	{
		"id": "33",
		"tagName": "policyCategory",
		"tagValue": "IaC Security Posture",
		"tagDescription": "",
		"createdBy": "system"
	}
	`,
}
