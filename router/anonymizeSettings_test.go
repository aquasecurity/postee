package router

import "testing"

func TestAnonymizeSettings(t *testing.T) {
	tests := []struct {
		original *ActionSettings
		expected *ActionSettings
	}{{
		&ActionSettings{
			User: "admin",
		},
		&ActionSettings{
			User: "<hidden>",
		},
	}, {
		&ActionSettings{
			User: "",
		},
		&ActionSettings{
			User: "",
		},
	}, {
		&ActionSettings{
			Password: "secret",
		},
		&ActionSettings{
			Password: "<hidden>",
		},
	}, {
		&ActionSettings{
			Url: "http://localhost",
		},
		&ActionSettings{
			Url: "<hidden>",
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
		if anonymized.Password != test.expected.Password {
			t.Errorf("Settings anonymization is incorrect: expected Password %s, got %s", test.expected.Password, anonymized.Password)
		}
		if anonymized.Url != test.expected.Url {
			t.Errorf("Settings anonymization is incorrect: expected Url %s, got %s", test.expected.Url, anonymized.Url)
		}
	}
}
