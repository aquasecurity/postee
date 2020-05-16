package layout

import (
	"bytes"
	"data"
	"strconv"
)

func GenTicketDescription(provider LayoutProvider, scanInfo, prevScan *data.ScanImageInfo) string {
	var builder bytes.Buffer
	builder.WriteString("Image name: " + scanInfo.Image + "\n")
	builder.WriteString("Registry: " + scanInfo.Registry + "\n" )
	if scanInfo.Disallowed {
		builder.WriteString("Image is non-compliant\n")
	} else {
		builder.WriteString("Image is compliant\n")
	}

	if scanInfo.ScanMalware {
		if scanInfo.Malware > 0 {
			builder.WriteString("Malware found: YES\n")
		} else {
			builder.WriteString("Malware found: No\n")
		}
	}

	if scanInfo.ScanSensitiveData {
		if scanInfo.Sensitive > 0 {
			builder.WriteString("Sensitive data found: yes\n")
		} else {
			builder.WriteString("Sensitive data found: No\n")
		}
	}

	builder.WriteString( VulnerabilitiesTable(provider, [2][]string {
		{"CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE"},
		{strconv.Itoa(scanInfo.Critical), strconv.Itoa(scanInfo.High), strconv.Itoa(scanInfo.Medium), strconv.Itoa(scanInfo.Low), strconv.Itoa(scanInfo.Negligible)},
	}))

	// Rendering Assurances
	if len(scanInfo.ImageAssuranceResults.ChecksPerformed) > 0 {
		builder.WriteString( provider.TitleH2("Assurance controls"))
		builder.WriteString( RenderAssurances(provider, scanInfo.ImageAssuranceResults))
	}

	// Rendering Found vulnerabilities
	if len(scanInfo.Resources) > 0 {
		builder.WriteString( provider.TitleH2("Found vulnerabilities"))
		for _, r := range scanInfo.Resources {
			builder.WriteString( provider.TitleH3("Resource name: "+ r.Name))
			builder.WriteString( RenderVulnerabilities( provider, r.Name, r.Vulnerabilities) )
		}
	}

	// Discovered vulnerabilities from last scan:
	if prevScan != nil && len(prevScan.Resources) > 0 {
		builder.WriteString("\n")
		builder.WriteString(provider.TitleH2("Discovered vulnerabilities from last scan"))
		for _, prev := range prevScan.Resources {
			builder.WriteString( provider.TitleH3("Resource name: "+ prev.Name))
			builder.WriteString(RenderVulnerabilities(provider, prev.Name, prev.Vulnerabilities))
		}
	}
	return builder.String()
}



