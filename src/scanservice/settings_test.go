package scanservice

import (
	"dbservice"
	"formatting"
	"layout"
	"os"
	"plugins"
	"settings"
	"testing"
)

func TestRemoveLowLevelVulnerabilities(t *testing.T) {
	var tests = []struct{
		input      string
		severities map[string]int
	} {
		/*{
			string(Bkmorrow),
			map[string]int{
				"critical":0,
				"high":0,
				"medium":2,
				"low":2,
				"negligible":2,
			},
		},
		 */
		{
			string(AlpineImageSource),
			map[string]int{
				"critical":0,
				"high":0,
				"medium":2,
				"low":2,
				"negligible":2,
			},
		},
	}

	dbPathReal := dbservice.DbPath
	defer func() {
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_" + dbPathReal

	setting :=  &settings.Settings{
		PolicyMinVulnerability: "",
		PolicyRegistry:         nil,
		PolicyImageName:        nil,
		PolicyNonCompliant:     false,
		IgnoreRegistry:         nil,
		IgnoreImageName:        nil,
	}

	plgs := map[string]plugins.Plugin {}
	plgs["demo"] = &DemoPlugin{
		name: "Demo plugin",
		lay:  new(formatting.HtmlProvider),
		sets: setting,
		t:    t,
	}

	for _, test := range tests {
		for severity, count := range test.severities {
			setting.PolicyMinVulnerability = severity

			service := new(ScanService)
			service.ResultHandling( test.input,  plgs )
			c := 0
			for _, r := range service.scanInfo.Resources {
				c += len(r.Vulnerabilities)
			}
			if c != count {
				t.Errorf("Wrong severity %q for %s\nResult: %d\nWaiting:%d\n",
					severity, service.scanInfo.GetUniqueId(), c, count)
			}
			os.Remove(dbservice.DbPath)
		}
	}
}

type DemoPlugin struct {
	name string
	lay  layout.LayoutProvider
	sets *settings.Settings
	t    *testing.T
}
func (plg *DemoPlugin) Init() error {	return nil}
func (plg *DemoPlugin) Send(data map[string]string) error {
	plg.t.Logf("Sending data from Demo plugin %s\n", plg.name)
	plg.t.Logf("Title: %q\n", data["title"])
	plg.t.Logf("Description: %q\n", data["description"])
	return nil
}

func (plg *DemoPlugin) Terminate() error { return nil}
func (plg *DemoPlugin) GetLayoutProvider() layout.LayoutProvider {
	return plg.lay
}
func (plg *DemoPlugin) GetSettings() *settings.Settings {
	return plg.sets
}