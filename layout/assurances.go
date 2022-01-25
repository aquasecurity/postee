package layout

import (
	"strconv"

	"github.com/aquasecurity/postee/v2/data"
)

func RenderAssurances(provider LayoutProvider, assuranceResults data.ImageAssuranceResults) string {
	var assurances [][]string
	assurances = append(assurances, []string{"#", "Control", "Policy Name", "Status"})

	for i, ass := range assuranceResults.ChecksPerformed {
		var status string
		if ass.Failed {
			status = "FAIL"
		} else {
			status = "PASS"
		}
		assurances = append(assurances, []string{
			strconv.Itoa(i + 1),
			ass.Control,
			ass.PolicyName,
			status,
		})
	}
	return provider.Table(assurances)
}
