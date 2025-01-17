package september2024october2024

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func translateComponents(dc []Component) (map[string]*AddComponentInput, error) {
	ret := map[string]*AddComponentInput{}
	purlExists := map[string]bool{}
	for _, c := range dc {
		if strings.ToLower(string(c.Type)) != "library" {
			continue
		}

		if c.Purl == nil {
			continue
		}

		if _, ok := purlExists[*c.Purl]; ok {
			continue
		}

		purlExists[*c.Purl] = true
		component, err := translateComponent(c)
		if err != nil {
			return nil, err
		}

		ret[string(*c.BomRef)] = component
	}
	return ret, nil
}

type AddComponentInput struct {
	Id        string     `json:"id"`
	Type      string     `json:"type"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Licenses  []string   `json:"licenses"`
	Purl      string     `json:"purl"`
	Cpe       string     `json:"cpe"`
	ScannedAt *time.Time `json:"scannedAt"`
}

type License struct {
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	Id   string `json:"id,omitempty" yaml:"id,omitempty"`
}

// LicenseWrapper represents the structure of the license object within the array
type LicenseWrapper struct {
	License License `json:"license,omitempty" yaml:"license,omitempty"`
}

func translateLicenses(dcl []map[string]interface{}) ([]string, error) {
	if dcl == nil {
		return nil, nil
	}

	jsonData, err := json.Marshal(dcl)
	if err != nil {
		return nil, err
	}

	var licenses []LicenseWrapper
	err = json.Unmarshal(jsonData, &licenses)
	if err != nil {
		return nil, err
	}

	ret := []string{}
	for _, value := range licenses {
		licensegot := value.License.Name
		if licensegot == "" {
			licensegot = value.License.Id
		}
		if licensegot == "" {
			continue
		}
		ret = append(ret, strings.ToLower(licensegot))
	}
	return unique(ret), nil
}

// unique will return a slice that contains only unique
// items.  The order of appearance is maintained, such
// that ["foo", "bar", "foo"] will always return ["foo", "bar"]
func unique[T comparable](s []T) []T {
	found := make(map[T]bool)
	result := []T{}
	for _, str := range s {
		if _, ok := found[str]; !ok {
			found[str] = true
			result = append(result, str)
		}
	}
	return result
}

func translateComponent(dc Component) (*AddComponentInput, error) {
	idArray := []string{*dc.Purl, "|", valueOrEmptyString(dc.Cpe)}

	licenses, err := translateLicenses(dc.Licenses)
	if err != nil {
		return nil, err
	}

	return &AddComponentInput{
		Id:       MakeID(idArray...),
		Type:     string(dc.Type),
		Name:     dc.Name,
		Version:  valueOrEmptyString(dc.Version),
		Purl:     *dc.Purl,
		Cpe:      valueOrEmptyString(dc.Cpe),
		Licenses: licenses,
	}, nil
}

func MakeID(items ...string) string {
	h := sha256.New()
	key := strings.Join(items, "|")
	h.Write([]byte(key))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func valueOrEmptyString(sp *string) string {
	if sp == nil {
		return ""
	}
	return *sp
}

func extractFileName(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsedURL.Query()
	return query.Get("fileName"), nil
}

func processFile(
	ctx context.Context,
	fileName string,
	s3Client *graphqlfunc.S3Client,
	gqlient graphql.Client,
	bucketName, keyPrefix string,
) error {
	logger.Sl.Debug("Processing file:", fileName)

	key := s3Client.MakeS3Key(bucketName, keyPrefix, fileName)
	if !s3Client.ObjectExists(ctx, bucketName, key) {
		return fmt.Errorf("file not found: %s", key)
	}

	savefile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("os.Create: error: %s", err)
	}
	defer os.Remove(fileName)

	if err := s3Client.Download(ctx, bucketName, key, savefile); err != nil {
		return fmt.Errorf("unable to download file: %s, error: %s", key, err.Error())
	}
	savefile.Close()

	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("os.ReadFile: error: %s", err.Error())
	}

	var dx CycloneDx
	if err := json.Unmarshal(data, &dx); err != nil {
		return fmt.Errorf("json.Unmarshal: error: %s", err.Error())
	}

	componentPointers, err := translateComponents(dx.Components)
	if err != nil {
		return fmt.Errorf("translateComponents: error: %s", err.Error())
	}

	for _, v := range componentPointers {
		if _, err := updateComponentLicense(ctx, gqlient, v.Id, v.Licenses); err != nil {
			return fmt.Errorf("updateComponentLicense: id: %s licenses: %v error: %s", v.Id, v.Licenses, err.Error())
		}
	}

	logger.Sl.Debug("Completed processing file:", fileName)
	return nil
}

func ingestLicenses(gqlient graphql.Client) error {

	logger.Sl.Debugf("-----ingesting licenses from sboms--------")

	s3Url, found := os.LookupEnv("S3_ENDPOINT_URL")
	if !found {
		return fmt.Errorf("envar S3_ENDPOINT_URL is not set")
	}

	totalComponents, err := totalCountOfComponents(context.Background(), gqlient)
	if err != nil {
		return fmt.Errorf("ingestLicenses: totalCountOfComponents: err: %s", err.Error())
	}

	var allComponents []*getAllComponentsQueryComponent
	for offset := 0; offset < *totalComponents.AggregateComponent.Count; offset += 1000 {
		components, err := getAllComponents(context.Background(), gqlient, &offset)
		if err != nil {
			return fmt.Errorf("ingestLicenses: getAllComponents: offset: %v err: %s", offset, err.Error())
		}
		allComponents = append(allComponents, components.QueryComponent...)
	}

	// Step 1: Count occurrences of each fileName
	fileNameCounts := make(map[string]int)
	componentFileNames := make(map[string][]string)

	for _, component := range allComponents {
		for _, artifact := range component.Artifacts {
			for _, scanFile := range artifact.ScanFile {
				fileName, err := extractFileName(scanFile.Url)
				if err != nil {
					logger.Logger.Sugar().Errorf("Error extracting fileName:", err.Error())
					continue
				}
				fileNameCounts[fileName]++
				componentFileNames[component.Id] = append(componentFileNames[component.Id], fileName)
			}
		}
	}

	// Step 2: Determine best fileName for each component
	componentTags := make(map[string]string, 0)

	for componentID, fileNames := range componentFileNames {
		type FileCount struct {
			FileName string
			Count    int
		}
		var fileCounts []FileCount

		// Collect counts for this component's fileNames
		for _, fileName := range fileNames {
			fileCounts = append(fileCounts, FileCount{fileName, fileNameCounts[fileName]})
		}

		// Sort by count (descending) and fallback to first entry if tie
		sort.Slice(fileCounts, func(i, j int) bool {
			if fileCounts[i].Count == fileCounts[j].Count {
				return fileCounts[i].FileName < fileCounts[j].FileName
			}
			return fileCounts[i].Count > fileCounts[j].Count
		})

		// Pick the best fileName and tag the component
		if len(fileCounts) > 0 {
			bestFileName := fileCounts[0].FileName
			componentTags[componentID] = bestFileName
		}
	}

	// reverse it by getting file to parse
	fileNameToComponents := make(map[string][]string)
	for component, file := range componentTags {
		if exists, ok := fileNameToComponents[file]; ok {
			exists = append(exists, component)
			fileNameToComponents[file] = exists
			continue
		}
		fileNameToComponents[file] = append(fileNameToComponents[file], component)
	}

	makeS3client, err := graphqlfunc.MakeS3Client(context.Background(), s3Url)
	if err != nil {
		return fmt.Errorf("ingestLicenses: MakeS3Client: err: %s", err.Error())
	}

	const numWorkers = 20
	fileChan := make(chan string, len(fileNameToComponents))
	var wg sync.WaitGroup

	processed := 0
	totalFiles := len(fileNameToComponents)

	// Worker pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fileName := range fileChan {
				if err := processFile(context.Background(), fileName, makeS3client, gqlient, "ssd-temporal", "sbom"); err != nil {
					logger.Logger.Sugar().Errorf("error processing file %s: %v", fileName, err.Error())
				}
				processed++
				logger.Logger.Sugar().Debugf("no. of file processed: %v  outOfFiles: %v", processed, totalFiles)
			}
		}()
	}

	// Enqueue tasks
	for fileName := range fileNameToComponents {
		fileChan <- fileName
	}
	close(fileChan)

	// Wait for all workers to finish
	wg.Wait()

	logger.Sl.Debugf("-----ingested licenses from sboms--------")

	return nil

}
