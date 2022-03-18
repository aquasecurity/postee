package msgservice

import (
	"strconv"
	"strings"
	"testing"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

var (
	AlpineImageResult = data.ScanImageInfo{
		Image:          "alpine:3.8",
		Registry:       "Docker Hub",
		Digest:         "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		PreviousDigest: "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		ImageAssuranceResults: data.ImageAssuranceResults{
			Disallowed: true,
			ChecksPerformed: []data.ControlCheck{
				{Control: "max_severity", PolicyName: "Default", Failed: false},
				{Control: "trusted_base_images", PolicyName: "Default", Failed: true},
				{Control: "max_score", PolicyName: "Default", Failed: false},
			},
		},
		VulnerabilitySummary: data.VulnerabilitySummary{
			Total: 2, Critical: 0, High: 0, Medium: 2, Low: 0, Negligible: 0, Sensitive: 0, Malware: 0,
		},
		ScanOptions: data.ScanOptions{ScanSensitiveData: true, ScanMalware: true},
		Resources: []data.InfoResources{
			{
				Vulnerabilities: []data.Vulnerability{
					{Name: "CVE-2018-20679", Version: "", FixVersion: "", Severity: "medium"},
					{Name: "CVE-2019-5747", Version: "", FixVersion: "", Severity: "medium"},
				},
				ResourceDetails: data.ResourceDetails{Name: "busybox", Version: "1.28.4-r3"},
			},
		},
	}

	AshexPokemongoResult = data.ScanImageInfo{
		Image:          "ashex/pokemongo-map:latest",
		Registry:       "Docker Hub",
		Digest:         "sha256:ecc79e40b241b1b3b2580c58619cbc4c73b833308d780ad035bf6bdfbb529435",
		PreviousDigest: "sha256:ecc79e40b241b1b3b2580c58619cbc4c73b833308d780ad035bf6bdfbb529435",
		ImageAssuranceResults: data.ImageAssuranceResults{
			Disallowed: true, ChecksPerformed: []data.ControlCheck{
				{Control: "trusted_base_images", PolicyName: "Default", Failed: true},
				{Control: "max_score", PolicyName: "Default", Failed: true},
				{Control: "max_severity", PolicyName: "Default", Failed: true},
			},
		},
		VulnerabilitySummary: data.VulnerabilitySummary{
			Total: 249, Critical: 2, High: 52, Medium: 184, Low: 11, Negligible: 34, Sensitive: 15, Malware: 0,
		},
		ScanOptions: data.ScanOptions{ScanSensitiveData: true, ScanMalware: true},
		Resources: []data.InfoResources{
			{
				Vulnerabilities: []data.Vulnerability{
					{Name: "WS-2018-0076", Version: "", FixVersion: "0.6.0", Severity: "negligible"},
					{Name: "", Version: "", FixVersion: "", Severity: ""},
				},
				ResourceDetails: data.ResourceDetails{Name: "", Version: ""},
			},
		},
		ApplicationScopeOwners: []string{"recipient1@aquasec.com", "recipient1@aquasec.com"},
	}
)

func getImportantData(scan *data.ScanImageInfo) map[string]string {
	important := make(map[string]string)

	important[scan.Image] = "scan.Image"
	important[scan.Registry] = ""
	important[strconv.Itoa(scan.Critical)] = "scan.Critical"
	important[strconv.Itoa(scan.High)] = "scan.High"
	important[strconv.Itoa(scan.Medium)] = "scan.Medium"
	important[strconv.Itoa(scan.Low)] = "scan.Low"
	important[strconv.Itoa(scan.Negligible)] = "scan.Negligible"

	for _, resource := range scan.Resources {
		important[resource.Name] = "resource.Name"
		important[resource.ResourceDetails.Name] = "resource.ResourceDetails.Name"
		for _, vuln := range resource.Vulnerabilities {
			important[vuln.Name] = "vuln.Name"
			important[vuln.Version] = "vuln.Version"
			important[vuln.FixVersion] = "vuln.FixVersion"
		}
	}

	for i, check := range scan.ChecksPerformed {
		index := strconv.Itoa(i + 1)
		important[check.PolicyName] = index + ".check.PolicyName"
		important[check.Control] = index + ".check.Control"

		pass := "PASS"
		if check.Failed {
			pass = "FAIL"
		}
		important[pass] = pass
	}
	return important
}

func Equal(A, B *data.ScanImageInfo) bool {
	if A.Image != B.Image || A.Registry != B.Registry ||
		A.ScanOptions != B.ScanOptions || A.VulnerabilitySummary != B.VulnerabilitySummary ||
		A.ImageAssuranceResults.Disallowed != B.ImageAssuranceResults.Disallowed ||
		len(A.ImageAssuranceResults.ChecksPerformed) != len(B.ImageAssuranceResults.ChecksPerformed) {
		return false
	}

	for i, v := range A.ImageAssuranceResults.ChecksPerformed {
		if B.ImageAssuranceResults.ChecksPerformed[i] != v {
			return false
		}
	}

	for i, v := range A.Resources {
		if len(v.Vulnerabilities) != len(B.Resources[i].Vulnerabilities) {
			return false
		}
		for j, vuln := range v.Vulnerabilities {
			if B.Resources[i].Vulnerabilities[j] != vuln {
				return false
			}
		}
	}
	return true
}

func BenchmarkGenTicketDescription(b *testing.B) {
	provider := new(formatting.JiraLayoutProvider)
	for i := 0; i < b.N; i++ {
		layout.GenTicketDescription(provider, &AlpineImageResult, nil, "https://demolab.aquasec.com/", "")
	}
}

func TestGenTicketDescription(t *testing.T) {
	var tests = []struct {
		currentScan  *data.ScanImageInfo
		previousScan *data.ScanImageInfo
	}{
		{&AlpineImageResult, nil},
		{&AshexPokemongoResult, nil},
	}

	providers := []layout.LayoutProvider{
		new(formatting.JiraLayoutProvider),
		new(formatting.HtmlProvider),
	}

	for _, provider := range providers {
		for _, test := range tests {
			got := layout.GenTicketDescription(provider, test.currentScan, test.previousScan, "https://demolab.aquasec.com", "")
			important := getImportantData(test.currentScan)
			for k, v := range important {
				if !strings.Contains(got, k) {
					t.Errorf("Rendered data (%s) doesn't contain important value:\n%s (%s)\n", got, k, v)
				}
			}
		}
	}
}

func TestGenTicketDescriptionFieldSeeMore(t *testing.T) {
	var tests = []struct {
		name           string
		serverUrl      string
		image_url_part string
		expectedSuffix string
	}{
		{"serverUrl is fill", "https://demolab.aquasec.com/", "alpine:3.9.6",
			"|CVE-2019-5747|busybox|1.28.4-r3|none|\n\nSee more: [https://demolab.aquasec.com/alpine:3.9.6|https://demolab.aquasec.com/alpine:3.9.6]\n"},
		{"serverUrl is empty", "", "alpine:3.9.6",
			"|CVE-2019-5747|busybox|1.28.4-r3|none|\n\n"},
	}

	provider := new(formatting.JiraLayoutProvider)
	scan := &AlpineImageResult

	for _, test := range tests {
		got := layout.GenTicketDescription(provider, scan, nil, test.serverUrl, test.image_url_part)
		if !strings.HasSuffix(got, test.expectedSuffix) {
			t.Errorf("Rendered data doesn't have expected suffix:%s, got:%s", test.expectedSuffix, got)
		}
	}

}
