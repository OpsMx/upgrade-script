package july2024august2024

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"upgradationScript/july2024august2024/july2024"

	"github.com/Khan/genqlient/graphql"
)

func getCredentials(orgName, key string, gqlClient graphql.Client) (SecretData, error) {

	resp, err := july2024.QueryIntegratorsForOrgByTypeIfConnected(context.TODO(), gqlClient, orgName, key, nil)
	if err != nil {
		return SecretData{}, fmt.Errorf("error: QueryIntegratorsForOrgByTypeIfConnected: orgName: %s type: %s %s", orgName, key, err.Error())
	}

	if len(resp.QueryOrganization) == 0 {
		return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: orgName: %s type: %s error: integrator might not be enabled", orgName, key)
	}

	if len(resp.QueryOrganization[0].Integrators[0].IntegratorConfigs) == 0 {
		return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: orgName: %s type: %s error: integrator might not be connected", orgName, key)
	}

	if len(resp.QueryOrganization) == 0 {
		return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: orgName: %s type: %s error: integrator might not be enabled", orgName, key)
	}

	if len(resp.QueryOrganization[0].Integrators[0].IntegratorConfigs) == 0 {
		return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: orgName: %s type: %s error: integrator might not be connected", orgName, key)
	}

	integrator := Integrator{
		Data: make(map[string]interface{}),
	}
	for _, integratorConfig := range resp.QueryOrganization[0].Integrators[0].IntegratorConfigs[0].Configs {

		if *integratorConfig.Encrypt {
			integratorConfig.Value, err = decryptSecretData(integratorConfig.Value)
			if err != nil {
				return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: type: %s configKey: %s err: %s", key, integratorConfig.Key, err.Error())
			}
		}

		integrator.Data[integratorConfig.Key] = integratorConfig.Value
	}

	secretParse := make(map[string]map[string]interface{})
	secretParse[key] = integrator.Data

	secretParseByte, err := json.Marshal(secretParse)
	if err != nil {
		return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: type: %s Marshal err: %s", key, err.Error())
	}

	var secretData SecretData
	if err := json.Unmarshal(secretParseByte, &secretData); err != nil {
		return SecretData{}, fmt.Errorf("getIntegratorDataForNonMulti: type: %s UnMarshal err: %s", key, err.Error())
	}

	return secretData, nil
}

func decryptSecretData(encryptedBase64EncodedString string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encryptedBase64EncodedString)
	if err != nil {
		return "", fmt.Errorf("decryptSecretData: decode error: %s", err.Error())
	}

	byteData, err := decryptAESWithGCM(decoded)
	if err != nil {
		return "", fmt.Errorf("decryptSecretData: decryption error: %s", err.Error())
	}

	return string(byteData), nil
}

func decryptAESWithGCM(ciphertext []byte) ([]byte, error) {

	secretKey, err := readFilePath(encryptionKeyPath)
	if err != nil {
		return nil, fmt.Errorf("fetchEncrytionKey: error: %s", err.Error())
	}

	aes, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, fmt.Errorf("decryptAESWithGCM: NewCipher: error: %s", err.Error())
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("decryptAESWithGCM: NewGCM: error: %s", err.Error())
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	byteArray, err := gcm.Open(nil, []byte(nonce), ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryptAESWithGCM: gcm.Open: error: %s", err.Error())
	}

	return byteArray, nil
}

func readFilePath(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error while reading file %s err:  %s", path, err.Error())
	}
	return key, nil
}

func getJiraTicketDetails(jiraKey, baseUrl, ursername, token string) (JiraIssueDetails, error) {

	jiraIssueUrl, err := url.JoinPath(baseUrl, JiraIssueApi, jiraKey)
	if err != nil {
		return JiraIssueDetails{}, fmt.Errorf("error: JoinPath: %s", err.Error())
	}

	req, err := http.NewRequest(http.MethodGet, jiraIssueUrl, nil)
	if err != nil {
		return JiraIssueDetails{}, fmt.Errorf("error: NewRequest: %s", err.Error())
	}

	req.SetBasicAuth(ursername, token)
	req.Header.Set("Content-Type", "application/json")

	encodedData, err := makeHTTPCallAndReadResponse(req)
	if err != nil {
		return JiraIssueDetails{}, fmt.Errorf("error: %s", err.Error())
	}

	var issueInfo JiraIssueDetails
	if err := json.Unmarshal(encodedData, &issueInfo); err != nil {
		return JiraIssueDetails{}, fmt.Errorf("error: Unmarshal: %s", err.Error())
	}
	return issueInfo, nil
}

func makeHTTPCallAndReadResponse(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("makeHTTPCallAndReadResponse: error: attempting to make a client call %s", err.Error())
	}

	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("makeHTTPCallAndReadResponse: error: in reading the response %s", err.Error())
	}

	if (resp.StatusCode == http.StatusCreated) || (resp.StatusCode == http.StatusOK) || (resp.StatusCode == http.StatusNoContent) {
		return content, nil
	}

	return content, fmt.Errorf("%s", resp.Status)
}
