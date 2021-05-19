package layout

import (
	"encoding/json"
	"errors"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/formatting"
)

type legacyScnEvaluator struct {
	layoutProvider LayoutProvider
}

func (legacyScnEvaluator *legacyScnEvaluator) Eval(in map[string]interface{}, serverUrl string) (string, error) {
	scan, err := toScanImage(in)
	if err != nil {
		return "", err
	}
	return GenTicketDescription(legacyScnEvaluator.layoutProvider, scan, nil, serverUrl), nil
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
