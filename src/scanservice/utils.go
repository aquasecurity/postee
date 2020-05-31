package scanservice

import (
	"bytes"
	"layout"
)

func buildMapContent(title, description string) map[string]string {
	content := make(map[string]string)
	content["title"] = title
	content["description"] = description
	return content
}

func buildAggregatedContent(scans []map[string]string, layoutProvider layout.LayoutProvider) map[string]string {
	var descr bytes.Buffer
	for _, scan := range scans {
		descr.WriteString(layoutProvider.TitleH1(scan["title"]))
		descr.WriteString(scan["description"])
	}
	title := "Vulnerability scan report"
	return buildMapContent(title, descr.String())
}
