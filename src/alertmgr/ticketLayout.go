package alertmgr

import (
	"bytes"
	"data"
	"encoding/json"
)

func GenTicketDescription(scanInfo, prevScan *data.ScanImageInfo) string {
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

	builder.WriteString(
		RenderVulnerabilitiesCounts(
			scanInfo.Critical, scanInfo.High, scanInfo.Medium, scanInfo.Low, scanInfo.Negligible ))

	// Rendering Assurances
	builder.WriteString( RenderAssurances(scanInfo.ImageAssuranceResults))

	// Rendering Found vulnerabilities
	if len(scanInfo.Resources) > 0 {
		builder.WriteString( "\nh2. Found vulnerabilities\n")
		for _, r := range scanInfo.Resources {
			v := RenderVulnerabilities( r.Name, r.Vulnerabilities)
			builder.WriteString( v )
		}
	}

	// Discovered vulnerabilities from last scan:
	if prevScan != nil && len(prevScan.Resources) > 0 {
		builder.WriteString("\nh2. Discovered vulnerabilities from last scan\n")
		for _, prev := range prevScan.Resources {
			builder.WriteString(RenderVulnerabilities(prev.Name, prev.Vulnerabilities))
		}
	}
	builder.WriteString("" + "\n")
	return builder.String()
}

func ParseImageInfo(source []byte) (*data.ScanImageInfo, error) {
	scanInfo := new(data.ScanImageInfo)
	err := json.Unmarshal(source, scanInfo)
	if err != nil {
		return nil, err
	}
	return scanInfo, nil
}

