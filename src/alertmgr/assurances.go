package alertmgr

import (
	"data"
	"fmt"
	"jiraformatting"
	"strconv"
	"strings"
)

func RenderAssurances(assuranceResults data.ImageAssuranceResults) (result string) {
	var assurances []string
	for i, ass := range assuranceResults.ChecksPerformed {
		var status string
		if ass.Failed {
			status = "FAIL"
		} else {
			status = "PASS"
		}
		assurances = append(assurances, jiraformatting.RenderTableRow(
			[]string {
				strconv.Itoa(i+1),
				ass.Control,
				ass.PolicyName,
				status,
			}))
	}
	if len(assurances) > 0 {
		title := jiraformatting.RenderTableTitle([]string{
			"#",
			"Control",
			"Policy Name",
			"Status",
		})
		result = fmt.Sprintf("h2. Assurance controls\n%s%s\n", title, strings.Join(assurances, ""))
	}
	return
}
