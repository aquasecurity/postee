package scanservice

type ScanSettings struct {
	PolicyMinVulnerability string
	PolicyRegistry []string
	PolicyImageName []string
	PolicyNonCompliant bool
}

func DefaultScanSettings() *ScanSettings {
	return &ScanSettings{
		PolicyMinVulnerability: "",
		PolicyRegistry:         []string{},
		PolicyImageName:        []string{},
		PolicyNonCompliant:     false,
	}
}
