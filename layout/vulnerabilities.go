package layout

import (
	"bytes"
	"github.com/aquasecurity/postee/data"
	"strings"
)

const empty = "none"

func RenderVulnerabilities(resources []data.InfoResources, provider LayoutProvider, builder *bytes.Buffer) {
	rating := make(map[string][][]string)
	for _, r := range resources {
		var resourceName, installedVersion string
		if r.ResourceDetails.Name == "" {
			resourceName = empty
		} else {
			resourceName = r.ResourceDetails.Name
		}
		if r.ResourceDetails.Version == "" {
			installedVersion = empty
		} else {
			installedVersion = r.ResourceDetails.Version
		}
		for _, v := range r.Vulnerabilities {
			var vulnerabilityId, fixVersion string
			if v.Name == "" {
				vulnerabilityId = empty
			} else {
				vulnerabilityId = v.Name
			}
			if v.FixVersion == "" {
				fixVersion = empty
			} else {
				fixVersion = data.ClearField(v.FixVersion)
			}
			key := strings.ToLower(v.Severity)
			rating[key] = append(rating[key], []string{vulnerabilityId, resourceName, installedVersion, fixVersion})
		}
	}
	order := [...]string{"critical", "high", "medium", "low", "negligible"}
	for _, title := range order {
		vulnerabilities, ok := rating[title]
		if !ok {
			continue
		}
		builder.WriteString(provider.TitleH3(strings.Title(title) + " severity vulnerabilities"))
		var table [][]string
		table = append(table, []string{"Vulnerability ID", "Resource name", "Installed version", "Fix version"})
		table = append(table, vulnerabilities...)
		builder.WriteString(provider.Table(table))
	}
}

func VulnerabilitiesTable(provider LayoutProvider, rows [2][]string) string {
	if len(rows) != 2 && len(rows[1]) != 5 {
		return ""
	}
	var table [][]string
	table = append(table, rows[0])
	var r []string
	r = append(r, provider.ColourText(rows[1][0], CriticalColor()))
	r = append(r, provider.ColourText(rows[1][1], HighColor()))
	r = append(r, provider.ColourText(rows[1][2], MediumColor()))
	r = append(r, provider.ColourText(rows[1][3], LowColor()))
	r = append(r, provider.ColourText(rows[1][4], NegligibleColor()))
	table = append(table, r)
	return provider.Table(table)
}
