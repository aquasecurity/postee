package scanservice

import (
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

	settings :=  DefaultScanSettings()
	for _, test := range tests {
		for severity, count := range test.severities {
			settings.PolicyMinVulnerability = severity

			service := new(ScanService)
			service.ResultHandling( test.input, settings, nil )
			c := 0
			for _, r := range service.scanInfo.Resources {
				c += len(r.Vulnerabilities)
			}
			if c != count {
				t.Errorf("Wrong severity %q for %s\nResult: %d\nWaiting:%d\n",
					severity, service.scanInfo.GetUniqueId(), c, count)
			}
		}

	}

}
