package scanservice

import (
	"bytes"
	"fmt"
	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/layout"
	"strings"
)

func getContent(scan, prev *data.ScanImageInfo, provider layout.LayoutProvider, server *string) map[string]string {
	url := scan.Registry + "/" + strings.ReplaceAll(scan.Image, "/", "%2F")
	return buildMapContent(
		fmt.Sprintf("%s vulnerability scan report", scan.Image),
		layout.GenTicketDescription(provider, scan, prev, *server+url),
		url)
}

func buildMapContent(title, description, url string) map[string]string {
	content := make(map[string]string)
	content["title"] = title
	content["description"] = description
	content["url"] = url
	return content
}

func buildAggregatedContent(scans []map[string]string, layoutProvider layout.LayoutProvider) map[string]string {
	var descr bytes.Buffer
	var urls bytes.Buffer
	for _, scan := range scans {
		descr.WriteString(layoutProvider.TitleH1(scan["title"]))
		descr.WriteString(scan["description"])
		if urls.Len() > 0 {
			urls.WriteByte('\n')
		}
		urls.WriteString(scan["url"])
	}
	title := "Vulnerability scan report"
	return buildMapContent(title, descr.String(), urls.String())
}
