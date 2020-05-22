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

	setting1 :=  &settings.Settings{
		PolicyMinVulnerability: "",
		PolicyRegistry:         nil,
		PolicyImageName:        nil,
		PolicyNonCompliant:     false,
		IgnoreRegistry:         nil,
		IgnoreImageName:        nil,
	}

	demoWithSettings := &DemoPlugin{
		name: "Demo plugin with settings",
		lay:  new(formatting.HtmlProvider),
		sets: setting1,
		t:    t,
	}
	demoWithoutSettings := &DemoPlugin{
		name: "Demo without settings",
		lay:   new(formatting.JiraLayoutProvider),
		sets: nil,
		t:    t,
	}

	plgs := map[string]plugins.Plugin {}
	plgs["demoSettings"] = demoWithSettings

	for _, test := range tests {
		for severity, count := range test.severities {
			setting1.PolicyMinVulnerability = severity

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

	plgs["demoWithoutSettings"]= demoWithoutSettings
	for _, test := range tests {
		total := 0
		for _, s := range test.severities {
			if s > total {
				total = s
			}
		}

		for severity, _ := range test.severities {
			setting1.PolicyMinVulnerability = severity

			service := new(ScanService)
			service.ResultHandling( test.input,  plgs )
			c := 0
			for _, r := range service.scanInfo.Resources {
				c += len(r.Vulnerabilities)
			}
			if c != total {
				t.Errorf("Wrong severity %q for %s\nResult: %d\nWaiting:%d\n",
					severity, service.scanInfo.GetUniqueId(), c, total)
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
	plg.t.Logf("Sending data via %q\n", plg.name)
//	plg.t.Logf("Title: %q\n", data["title"])
//	plg.t.Logf("Description: %q\n", data["description"])
	return nil
}

func (plg *DemoPlugin) Terminate() error { return nil}
func (plg *DemoPlugin) GetLayoutProvider() layout.LayoutProvider {
	return plg.lay
}
func (plg *DemoPlugin) GetSettings() *settings.Settings {
	return plg.sets
}