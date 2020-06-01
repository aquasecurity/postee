package scanservice

import (
	"dbservice"
	"formatting"
	"os"
	"plugins"
	"settings"
	"testing"
)

var (
	mockScanWithFix = `{
"image":"Demo mock image with Fix version",
"registry":"registry5",
"resources":[
	{
		"vulnerabilities":[
			{"name":"registry5-vuln1","fix_version":""},
			{"name":"registry5-vuln2","fix_version":"fix_version1"}
		]
	},
	{
		"vulnerabilities": [
			{"name":"registry5-vuln3","fix_version":""},
			{"name":"registry5-vuln4","fix_version":""}
		]
	}
]
}`


	mockScanWithoutFix = `{
"image":"Demo mock image without Fix version",
"registry":"registry5",
"resources":[
	{
		"vulnerabilities":[
			{"name":"registry5-vuln5","fix_version":""},
			{"name":"registry5-vuln6","fix_version":""}
		]
	},
	{
		"vulnerabilities": [
			{"name":"registry5-vuln7","fix_version":""},
			{"name":"registry5-vuln8","fix_version":""}
		]
	}
]
}`
)

func TestRemoveLowLevelVulnerabilities(t *testing.T) {
	var tests = []struct{
		input      string
		severities map[string]bool
	} {
		{
			string(AlpineImageSource),
			map[string]bool{
				"critical": false,
				"high": false,
				"medium":true,
				"low":true,
				"negligible":true,
			},
		},
	}

	dbPathReal := dbservice.DbPath
	defer func() {
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_" + dbPathReal

	setting1 :=  &settings.Settings{
		PluginName: "Demo plugin with settings",
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

	for _, test := range tests {
		for severity, needSending := range test.severities {
			setting1.PolicyMinVulnerability = severity
			plgs := map[string]plugins.Plugin {}
			demoWithSettings.Sent = false
			plgs["demoSettings"] = demoWithSettings

			service := new(ScanService)
			service.ResultHandling( test.input,  plgs )

			if needSending != demoWithSettings.Sent {
				t.Errorf("The notify was sent with wrong severity %q for %q\n",
					severity, service.scanInfo.GetUniqueId())
			}
			os.Remove(dbservice.DbPath)
		}
	}

	demoWithoutSettings := &DemoPlugin{
		name: "Demo without settings",
		lay:   new(formatting.JiraLayoutProvider),
		sets: nil,
		t:    t,
	}
	for _, test := range tests {
		for range test.severities {
			plgs := map[string]plugins.Plugin {}
			demoWithoutSettings.Sent = false
			plgs["demoWithoutSettings"]= demoWithoutSettings
			service := new(ScanService)
			service.ResultHandling( test.input,  plgs )
			if !demoWithoutSettings.Sent {
				t.Errorf("The notify wasn't sent for plugin without settings for %q\n",
					service.scanInfo.GetUniqueId())
			}
			os.Remove(dbservice.DbPath)
		}
	}
}

func TestPolicySettings(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_" + dbPathReal
	os.Remove(dbservice.DbPath)

	setting1 :=  &settings.Settings{
		PolicyImageName:[]string{"image1", "image2", },
	}
	demoEmailPlg := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting1,
	}
	plugins := map[string]plugins.Plugin {
		"Demo Email Plugin": &demoEmailPlg,
	}

	srv := new(ScanService)

	// -- Test PolicyImageName
	srv.ResultHandling(mockScan1, plugins)
	srv.ResultHandling(mockScan2, plugins)
	srv.ResultHandling(mockScan3, plugins)
	srv.ResultHandling(mockScan4, plugins)
	srv.ResultHandling(mockScan5, plugins)
	if demoEmailPlg.emailCounts != 2 {
		t.Errorf("Rule PolicyImageName. Wrong count of emails\nSent: %d\nWait:%d", demoEmailPlg.emailCounts, 2)
	}
	os.Remove(dbservice.DbPath)

	//-- Policy-Registry
	demoEmailPlg.emailCounts = 0
	setting1.PolicyRegistry = []string{"registry5", "REGistry4", "Registry3"}
	setting1.PolicyImageName = []string{}

	srv.ResultHandling(mockScan1, plugins)
	srv.ResultHandling(mockScan2, plugins)
	srv.ResultHandling(mockScan3, plugins)
	srv.ResultHandling(mockScan4, plugins)
	srv.ResultHandling(mockScan5, plugins)
	if demoEmailPlg.emailCounts != 3 {
		t.Errorf("Rule Policy-Registry. Wrong count of emails\nSent: %d\nWait:%d", demoEmailPlg.emailCounts, 3)
	}
	os.Remove(dbservice.DbPath)

	//-- Ignore-Registry
	demoEmailPlg.emailCounts = 0
	setting1.IgnoreRegistry = []string{"registry5", "REGistry4", "Registry3"}
	setting1.PolicyRegistry = []string{}
	srv.ResultHandling(mockScan1, plugins)
	srv.ResultHandling(mockScan2, plugins)
	srv.ResultHandling(mockScan3, plugins)
	srv.ResultHandling(mockScan4, plugins)
	srv.ResultHandling(mockScan5, plugins)
	if demoEmailPlg.emailCounts != 2 {
		t.Errorf("Rule Ignore-Registry. Wrong count of emails\nSent: %d\nWait:%d", demoEmailPlg.emailCounts, 2)
	}
	os.Remove(dbservice.DbPath)

	//-- Ignore-Image-Name
	demoEmailPlg.emailCounts = 0
	setting1.IgnoreRegistry = []string{}
	setting1.IgnoreImageName = []string{"image1", "image2", }
	srv.ResultHandling(mockScan1, plugins)
	srv.ResultHandling(mockScan2, plugins)
	srv.ResultHandling(mockScan3, plugins)
	srv.ResultHandling(mockScan4, plugins)
	srv.ResultHandling(mockScan5, plugins)
	if demoEmailPlg.emailCounts != 3 {
		t.Errorf("Rule Ignore-Image-Name. Wrong count of emails\nSent: %d\nWait:%d", demoEmailPlg.emailCounts, 3)
	}
	os.Remove(dbservice.DbPath)

	//--	Policy-Min-Vulnerability
	setting1.IgnoreImageName = []string{}

	tests := []struct{
		level string
		waiting int
	}{
		{"critical", 1},
		{"high", 2},
		{"medium", 3},
		{"low", 4},
		{"negligible", 5},
	}

	for _, test := range tests {
		demoEmailPlg.emailCounts = 0
		setting1.PolicyMinVulnerability = test.level
		srv.ResultHandling(mockScan1, plugins)
		srv.ResultHandling(mockScan2, plugins)
		srv.ResultHandling(mockScan3, plugins)
		srv.ResultHandling(mockScan4, plugins)
		srv.ResultHandling(mockScan5, plugins)
		if demoEmailPlg.emailCounts != test.waiting {
			t.Errorf("Wrong count of vulnerabilities for %q\nResult: %d\nWaiting: %d\n",
				test.level, demoEmailPlg.emailCounts, test.waiting)
		}
		os.Remove(dbservice.DbPath)
	}

	//-- PolicyNonCompliant
	demoEmailPlg.emailCounts = 0
	setting1.PolicyMinVulnerability = ""
	setting1.PolicyNonCompliant=true
	srv.ResultHandling(mockScan1, plugins)
	srv.ResultHandling(mockScan2, plugins)
	srv.ResultHandling(mockScan3, plugins)
	srv.ResultHandling(mockScan4, plugins)
	srv.ResultHandling(mockScan5, plugins)
	if demoEmailPlg.emailCounts != 4 {
		t.Errorf("Rule PolicyNonCompliant. Wrong count of emails\nSent: %d\nWait:%d", demoEmailPlg.emailCounts, 4)
	}
	os.Remove(dbservice.DbPath)

	//-- PolicyOnlyFixAvailable
	demoEmailPlg.emailCounts = 0
	setting1.PolicyNonCompliant=false
	setting1.PolicyOnlyFixAvailable=true
	srv.ResultHandling(mockScanWithFix, plugins)
	srv.ResultHandling(mockScanWithoutFix, plugins)
	if demoEmailPlg.emailCounts != 1 {
		t.Errorf("Rule PolicyOnlyFixAvailable. Wrong count of emails\nSent: %d\nWait:%d",
			demoEmailPlg.emailCounts, 1)
	}
}


