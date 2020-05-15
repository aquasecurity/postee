package alertmgr

import (
	"bytes"
	"data"
	"fmt"
	"jiraformatting"
	"strconv"
)

func RenderVulnerabilitiesCounts( critical, high, medium, low, negligible int) string {
	title := jiraformatting.RenderTableTitle([]string {
		"CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE",
	})
	row := jiraformatting.RenderTableRow([]string{
		jiraformatting.RenderColourIntField(critical, getCriticalColor()),
		jiraformatting.RenderColourIntField(high, getHighColor()),
		jiraformatting.RenderColourIntField(medium, getMediumColor()),
		jiraformatting.RenderColourIntField(low, getLowColor()),
		jiraformatting.RenderColourIntField(negligible, getNegligibleColor()),
	})
	return fmt.Sprintf("%s%s\n", title, row)
}

func RenderVulnerabilities(title string, vulns []data.Vulnerability) string {
	const empty = "none"
	var builder bytes.Buffer
	if title == "" {title = empty}
	builder.WriteString("h3. Resource name: "+title + "\n")
	builder.WriteString( jiraformatting.RenderTableTitle([]string{
		"#", "Name", "Version", "Fix version",
	}))
	for i, v := range vulns {
		var name, version, fixVersion string
		if v.Name == "" {name = empty} else { name = v.Name}
		if v.Version == "" { version = empty} else {version =v.Version}
		if v.FixVersion == "" { fixVersion = empty} else { fixVersion = jiraformatting.ClearField(v.FixVersion)}

		row := jiraformatting.RenderTableRow([]string{
			strconv.Itoa(i+1),
			name,
			version,
			fixVersion,
		})
		builder.WriteString( row )
	}
	return builder.String()
}

func getCriticalColor() string {	return "#c00000" }
func getHighColor() string {	return "#e0443d" }
func getMediumColor() string {	return "#f79421" }
func getLowColor() string {	return "#e1c930" }
func getNegligibleColor() string {	return "green" }
