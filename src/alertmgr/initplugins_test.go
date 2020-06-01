package alertmgr

import (
	"plugins"
	"testing"
)

var (
	slack_cfg = `
- name: my-slack
  type: slack
  enable: false
  url: "https://hooks.slack.com/services/TT/BBB/WWWW"
`
)

func TestBuildSlackPlugin(t *testing.T) {
	tests := []struct{
		pluginSettings PluginSettings
		slack plugins.SlackPlugin
	} {
		{
			PluginSettings{
				Name:                   "my-slack",
				Type:                   "slack",
				Enable:                 true,
				Url:                    "https://hooks.slack.com/services/TT/BBB/WWWW",
			},
			plugins.SlackPlugin{
				Url:           "https://hooks.slack.com/services/TT/BBB/WWWW",
				SlackSettings: nil,
			},
		},
	}

	for _, test := range tests {
		r := buildSlackPlugin( &test.pluginSettings)
		if r.Url != test.slack.Url {
			t.Errorf("Wrong url for Slack plugin\nWaited: %q\nResult: %q", test.slack.Url, r.Url)
		}
	}


}
