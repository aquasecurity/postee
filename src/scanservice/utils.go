package scanservice

import (
	"bytes"
	"layout"
)

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
		urls.WriteString( scan["url"] )
	}
	title := "Vulnerability scan report"
	return buildMapContent(title, descr.String(), urls.String())
}
