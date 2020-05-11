package alertmgr

type ScanImageInfo struct {
	Image string `json:"image"`
	Registry string `json:"registry"`

	ImageAssuranceResults    `json:"image_assurance_results"`
	VulnerabilitySummary `json:"vulnerability_summary"`
	ScanOptions `json:"scan_options"`
}

type ImageAssuranceResults struct {
	Disallowed bool `json:"disallowed"`
	ChecksPerformed []ControlCheck `json:"checks_performed"`
}

type ControlCheck struct {
	Control string `json:"control"`
	PolicyName string `json:"policy_name"`
	Failed bool `json:"failed"`
}

type ScanOptions struct {
	ScanSensitiveData bool `json:"scan_sensitive_data"`
	ScanMalware bool `json:"scan_malware"`
}

type VulnerabilitySummary struct {
	Total int `json:"total"`
	Critical int `json:"critical"`
	High int `json:"high"`
	Medium int `json:"medium"`
	Low int `json:"low"`
	Negligible int `json:"negligible"`
	Sensitive int `json:"sensitive"`
	Malware int `json:"malware"`
}

func (A *ScanImageInfo) Equal( B *ScanImageInfo) bool {
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
	return true
}