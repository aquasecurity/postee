package settings

type Settings struct {
	PolicyMinVulnerability string
	PolicyRegistry         []string
	PolicyImageName        []string
	PolicyNonCompliant     bool
	IgnoreRegistry         []string
	IgnoreImageName        []string
}