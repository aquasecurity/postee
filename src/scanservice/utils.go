package scanservice

import (
	"bytes"
	"fmt"
	"layout"
	"strings"
)

func buildMapContent(title, description, name string) map[string]string {
	content := make(map[string]string)
	content["name"] = name
	content["title"] = title
	content["description"] = description
	return content
}

func buildAggregatedContent(scans []map[string]string, layoutProvider layout.LayoutProvider) map[string]string {
	var descr bytes.Buffer
	var names []string
	for _, scan := range scans {
		descr.WriteString(layoutProvider.TitleH1(scan["title"]))
		descr.WriteString(scan["description"])
		if len(scan["name"]) > 0 {
			names = append(names, scan["name"])
		}
	}
	title := fmt.Sprintf("%s vulnerabilities scan report", strings.Join(names, ", "))
	return buildMapContent(title, descr.String(), "")
}
