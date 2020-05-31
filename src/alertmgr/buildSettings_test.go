package alertmgr

import (
	"settings"
	"testing"
)

func TestBuildSettings(t *testing.T){
	tests := []struct{
		sourceSettings *PluginSettings
		waitSettings *settings.Settings
	} {
		{
			&PluginSettings{
				Name:                   "Timeout without suffix",
				AggregateIssuesNumber:  7,
				AggregateIssuesTimeout: "2",
			},
			&settings.Settings{
				PluginName:              "Timeout without suffix",
				AggregateIssuesNumber:   7,
				AggregateTimeoutSeconds: 2,
			},
		},
		{
			&PluginSettings{
				Name:                   "Timeout 3h",
				AggregateIssuesNumber:  7,
				AggregateIssuesTimeout: "3h",
			},
			&settings.Settings{
				PluginName:              "Timeout 3h",
				AggregateIssuesNumber:   7,
				AggregateTimeoutSeconds: 10800,
			},
		},
		{
			&PluginSettings{
				Name:                   "Wrong timeout",
				AggregateIssuesNumber:  7,
				AggregateIssuesTimeout: "2d",
			},
			&settings.Settings{
				PluginName:              "Wrong timeout",
				AggregateIssuesNumber:   7,
				AggregateTimeoutSeconds: 0,
			},
		},
	}

	for _ , test := range tests {
		result := buildSettings(test.sourceSettings)
		if result.PluginName != test.waitSettings.PluginName {
			t.Errorf("Wrong getting 'PluginName'\nResult: %q\nWanted: %q",
				result.PluginName, test.waitSettings.PluginName)
		}
		if result.AggregateTimeoutSeconds != test.waitSettings.AggregateTimeoutSeconds {
			t.Errorf("Wrong getting 'AggregateIssuesTimeout': %q\nResult: %d\nWanted: %d",
				test.sourceSettings.AggregateIssuesTimeout, result.AggregateTimeoutSeconds, test.waitSettings.AggregateTimeoutSeconds)
		}
		if result.AggregateIssuesNumber != test.waitSettings.AggregateIssuesNumber {
			t.Errorf("Wrong getting 'AggregateIssuesTimeout': %q\nResult: %d\nWanted: %d",
				test.sourceSettings.AggregateIssuesNumber, result.AggregateIssuesNumber, test.waitSettings.AggregateIssuesNumber)
		}
	}
}
