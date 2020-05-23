package settings

type Settings struct {
	PolicyMinVulnerability string
	PolicyRegistry         []string
	PolicyImageName        []string
	PolicyNonCompliant     bool
	IgnoreRegistry         []string
	IgnoreImageName        []string
}

func GetDefaultSettings() *Settings {
	return &Settings{
		PolicyMinVulnerability: "",
		PolicyRegistry:         []string{},
		PolicyImageName:        []string{},
		PolicyNonCompliant:     false,
		IgnoreRegistry:         []string{},
		IgnoreImageName:        []string{},
	}
}