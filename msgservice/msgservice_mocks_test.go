package msgservice

import (
	"log"
	"strings"
	"sync"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

var (
	mockScan1 = map[string]interface{}{"image": "Demo mock image1", "registry": "registry1", "vulnerability_summary": map[string]int{"critical": 0, "high": 1, "medium": 3, "low": 4, "negligible": 5}, "image_assurance_results": map[string]interface{}{"disallowed": true}}
	mockScan2 = map[string]interface{}{"image": "Demo mock Image2", "registry": "registry2", "vulnerability_summary": map[string]int{"critical": 0, "high": 0, "medium": 3, "low": 4, "negligible": 5}, "image_assurance_results": map[string]interface{}{"disallowed": false}}
	mockScan3 = map[string]interface{}{"image": "Demo mock Image3", "registry": "Registry3", "vulnerability_summary": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 4, "negligible": 5}, "image_assurance_results": map[string]interface{}{"disallowed": true}}
	mockScan4 = map[string]interface{}{"image": "Demo mock image4", "registry": "registry4", "vulnerability_summary": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 5}, "image_assurance_results": map[string]interface{}{"disallowed": true}}
)

type DemoInptEval struct {
	rndMu         sync.Mutex
	aggrMu        sync.Mutex
	renderCnt     int
	aggrCnt       int
	skipAggrSpprt bool
}

func (inptEval *DemoInptEval) Eval(in map[string]interface{}, serverUrl string) (map[string]string, error) {
	inptEval.rndMu.Lock()
	inptEval.renderCnt++
	inptEval.rndMu.Unlock()
	title := "non-image"

	if img, ok := in["image"]; ok {
		title = img.(string)
	}

	return map[string]string{
		"title":       title,
		"description": title,
	}, nil
}
func (inptEval *DemoInptEval) BuildAggregatedContent(items []map[string]string) (map[string]string, error) {
	inptEval.aggrMu.Lock()
	inptEval.aggrCnt++
	inptEval.aggrMu.Unlock()

	agrTitle := []string{}
	agrDescription := []string{}
	for _, item := range items {
		agrTitle = append(agrTitle, item["title"])
		agrDescription = append(agrDescription, item["description"])
	}

	return map[string]string{
		"title":       strings.Join(agrTitle, ","),
		"description": strings.Join(agrDescription, ","),
	}, nil
}
func (inptEval *DemoInptEval) IsAggregationSupported() bool {
	return !inptEval.skipAggrSpprt
}

type DemoEmailOutput struct {
	wg          *sync.WaitGroup
	mu          sync.Mutex
	payloads    []map[string]string
	emailCounts int
}

func (plg *DemoEmailOutput) GetType() string {
	return ""
}

func (plg *DemoEmailOutput) GetName() string {
	return "demo"
}
func (plg *DemoEmailOutput) CloneSettings() *data.OutputSettings {
	return nil
}

func (plg *DemoEmailOutput) getEmailsCount() int {
	plg.mu.Lock()
	e := plg.emailCounts
	plg.mu.Unlock()
	return e
}

func (plg *DemoEmailOutput) Init() error { return nil }
func (plg *DemoEmailOutput) Send(data map[string]string) (string, error) {
	log.Printf("Sending through demo plugin..\n")
	log.Printf("%s\n", data["title"])

	plg.mu.Lock()
	plg.emailCounts++
	plg.payloads = append(plg.payloads, data)
	plg.mu.Unlock()
	if plg.wg != nil {
		plg.wg.Done()
	}
	return "", nil
}

func (plg *DemoEmailOutput) Terminate() error { return nil }
func (plg *DemoEmailOutput) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}
