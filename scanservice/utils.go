package scanservice

import (
	"bytes"
	"github.com/aquasecurity/postee/layout"
	"strings"
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
	owners := []string{}
	for _, scan := range scans {
		descr.WriteString(layoutProvider.TitleH1(scan["title"]))
		descr.WriteString(scan["description"])
		if urls.Len() > 0 {
			urls.WriteByte('\n')
		}
		urls.WriteString(scan["url"])
		if len(scan["owners"]) > 0 {
			owners = append(owners, scan["owners"])
		}
	}
	title := "Vulnerability scan report"
	r := buildMapContent(title, descr.String(), urls.String())
	if len(owners) > 0 {
		r["owners"] = strings.Join(owners, ";")
	}
	return r
}
