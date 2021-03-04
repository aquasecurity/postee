package alertmgr

import (
	"io/ioutil"
	"os"
	"settings"
	"testing"
)

func TestBuildSettings(t *testing.T) {
	tests := []struct {
		sourceSettings *PluginSettings
		waitSettings   *settings.Settings
	}{
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

	for _, test := range tests {
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

	// OPA/REGO policy test
	realFile := "opa.rego"
	if err := ioutil.WriteFile(realFile, []byte("rego"), 0666); err != nil {
		t.Errorf("Can't create a demo file (%q) with rego policy: %v", realFile, err)
		return
	}
	wrongfile := "://wrongfile"
	nofile := "nofile"

	osStat = func(name string) (os.FileInfo, error) {
		switch name {
		case nofile:
			return nil, os.ErrNotExist
		case wrongfile:
			return nil, os.ErrClosed
		}
		return nil, nil
	}
	defer func() {
		osStat = os.Stat
		os.RemoveAll(realFile)
	}()

	sourceSettings := &PluginSettings{
		PolicyOPA: []string{
			realFile,
			wrongfile,
			nofile,
		},
	}

	builtSettings := buildSettings(sourceSettings)
	if len(builtSettings.PolicyOPA) != 1 {
		t.Errorf("buildSettings returned undefined rego policy files %v", builtSettings.PolicyOPA)
		return
	}
	if builtSettings.PolicyOPA[0] != realFile {
		t.Errorf("buildSettings returned an undefined policy file: %q, waited: %q", builtSettings.PolicyOPA[0], realFile)
	}
}
