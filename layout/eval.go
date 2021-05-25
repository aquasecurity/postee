package layout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/formatting"
)

type legacyScnEvaluator struct {
	layoutProvider LayoutProvider
}

func (legacyScnEvaluator *legacyScnEvaluator) Eval(in map[string]interface{}, serverUrl string) (map[string]string, error) {
	scan, err := toScanImage(in)
	if err != nil {
		return nil, err
	}
	title := fmt.Sprintf("%s vulnerability scan report", in["image"])

	return map[string]string{

		"title":       title,
		"description": GenTicketDescription(legacyScnEvaluator.layoutProvider, scan, nil, serverUrl),
		"url":         serverUrl,
	}, nil
}
func (legacyScnEvaluator *legacyScnEvaluator) IsAggregationSupported() bool {
	return true
}

func (legacyScnEvaluator *legacyScnEvaluator) BuildAggregatedContent(scans []map[string]string) (map[string]string, error) {
	var descr bytes.Buffer
	var urls bytes.Buffer
	for _, scan := range scans {
		descr.WriteString(legacyScnEvaluator.layoutProvider.TitleH1(scan["title"]))
		descr.WriteString(scan["description"])
		if urls.Len() > 0 {
			urls.WriteByte('\n')
		}
		urls.WriteString(scan["url"])
	}
	title := "Vulnerability scan report"

	return map[string]string{
		"title":       title,
		"description": descr.String(),
		"url":         urls.String(), //TODO this is strange ...
	}, nil

}

func toScanImage(in map[string]interface{}) (*data.ScanImageInfo, error) {
	source, err := json.Marshal(in) //back to bytes
	if err != nil {
		return nil, err
	}

	scanInfo := new(data.ScanImageInfo)

	err = json.Unmarshal(source, scanInfo)
	if err != nil {
		return nil, err
	}
	return scanInfo, nil
}

func BuildLegacyScnEvaluator(layoutType string) (data.Inpteval, error) {
	switch layoutType {
	case "slack":
		return &legacyScnEvaluator{
			layoutProvider: &formatting.SlackMrkdwnProvider{},
		}, nil
	case "html":
		return &legacyScnEvaluator{
			layoutProvider: &formatting.HtmlProvider{},
		}, nil
	case "jira":
		return &legacyScnEvaluator{
			layoutProvider: &formatting.JiraLayoutProvider{},
		}, nil
	default:
		return nil, errors.New("unknown layout type")
	}
}
