package alertmgr

import "testing"

func TestAnonymizeSettings(t *testing.T) {
	tests := []struct {
		original *PluginSettings
		expected *PluginSettings
	}{{
		&PluginSettings{
			User: "admin",
		},
		&PluginSettings{
			User: "<hidden>",
		},
	}, {
		&PluginSettings{
			User: "",
		},
		&PluginSettings{
			User: "",
		},
	}, {
		&PluginSettings{
			Password: "secret",
		},
		&PluginSettings{
			Password: "<hidden>",
		},
	}, {
		&PluginSettings{
			Url: "http://localhost",
		},
		&PluginSettings{
			Url: "<hidden>",
		},
	}, {
		&PluginSettings{
			PolicyShowAll: false,
		},
		&PluginSettings{
			PolicyShowAll: false,
		},
	}, {
		&PluginSettings{
			PolicyRegistry: []string{"alpine", "Docker image", "Docker hub"},
		},
		&PluginSettings{
			PolicyRegistry: []string{"alpine", "Docker image", "Docker hub"},
		},
	},
	}

	for _, test := range tests {
		anonymized := anonymizeSettings(test.original)
		if anonymized == test.original {
			t.Errorf("Anonymized settings weren't cloned")
		}
		if anonymized.User != test.expected.User {
			t.Errorf("Settings anonymization is incorrect: expected User %s, got %s", test.expected.User, anonymized.User)
		}
		for i := 0; i < len(test.expected.PolicyRegistry); i++ {
			if anonymized.PolicyRegistry[i] != test.expected.PolicyRegistry[i] {
				t.Errorf("Settings anonymization is incorrect: expected PolicyRegistry %s, got %s", test.expected.PolicyRegistry[i], anonymized.PolicyRegistry[i])
			}

		}
		if anonymized.PolicyShowAll != test.expected.PolicyShowAll {
			t.Errorf("Settings anonymization is incorrect: expected PolicyShowAll %t, got %t", test.expected.PolicyShowAll, anonymized.PolicyShowAll)
		}
		if anonymized.Password != test.expected.Password {
			t.Errorf("Settings anonymization is incorrect: expected Password %s, got %s", test.expected.Password, anonymized.Password)
		}
		if anonymized.Url != test.expected.Url {
			t.Errorf("Settings anonymization is incorrect: expected Url %s, got %s", test.expected.Url, anonymized.Url)
		}
	}
}
