package scanservice

type ScanSettings struct {
	PolicyMinVulnerability string
	PolicyRegistry         []string
	PolicyImageName        []string
	PolicyNonCompliant     bool

	IgnoreRegistry  []string
	IgnoreImageName [] string
}

func DefaultScanSettings() *ScanSettings {
	return &ScanSettings{
		PolicyMinVulnerability: "",
		PolicyRegistry:         []string{},
		PolicyImageName:        []string{},
		PolicyNonCompliant:     false,
		IgnoreRegistry:         []string{},
		IgnoreImageName:        []string{},
	}
}
