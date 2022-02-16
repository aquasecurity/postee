package router

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/aquasecurity/postee/v2/data"
)

func TestBuildAndInitOtpt(t *testing.T) {
	tests := []struct {
		caseDesc            string
		outputSettings      data.OutputSettings
		expctdProps         map[string]interface{}
		shouldFail          bool
		expectedOutputClass string
	}{
		{
			"Default Stdout Output",
			data.OutputSettings{
				Name:   "stdout",
				Type:   "stdout",
				Enable: true,
			},
			map[string]interface{}{
				"Name": "stdout",
			},
			false,
			"*outputs.StdoutOutput",
		},
		{
			"Simple Slack",
			data.OutputSettings{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/TT/BBB/WWWW",
			},
			map[string]interface{}{
				"Url":  "https://hooks.slack.com/services/TT/BBB/WWWW",
				"Name": "my-slack",
			},
			false,
			"*outputs.SlackOutput",
		},
		{
			"Simple Email output",
			data.OutputSettings{
				User:       "EmailUser",
				Password:   "pAsSw0rD",
				Host:       "smtp.gmail.com",
				Name:       "my-email",
				Type:       "email",
				Port:       587,
				Sender:     "google@gmail.com",
				Recipients: []string{"r1@gmail.com"},
			},
			map[string]interface{}{
				"User":       "EmailUser",
				"Password":   "pAsSw0rD",
				"Host":       "smtp.gmail.com",
				"Port":       587,
				"Sender":     "google@gmail.com",
				"Recipients": []string{"r1@gmail.com"},
			},
			false,
			"*outputs.EmailOutput",
		},
		{
			"Simple Jira output",
			data.OutputSettings{
				Url:        "localhost:2990",
				User:       "admin",
				Password:   "admin",
				Name:       "my-jira",
				Type:       "jira",
				ProjectKey: "PK",
				IssueType:  "IssueType",
				Priority:   "Priority",
				Assignee:   []string{"Assignee"},
			},
			map[string]interface{}{
				"Url":        "localhost:2990",
				"User":       "admin",
				"Password":   "admin",
				"ProjectKey": "PK",
				"Issuetype":  "IssueType",
				"Priority":   "Priority",
				"Assignee":   []string{"Assignee"},
			},
			false,
			"*outputs.JiraAPI",
		},
		{
			"Jira output without credentials",
			data.OutputSettings{
				Url:        "localhost:2990",
				Name:       "my-jira",
				Type:       "jira",
				ProjectKey: "PK",
				IssueType:  "IssueType",
				Priority:   "Priority",
				Assignee:   []string{"Assignee"},
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"Jira output without password",
			data.OutputSettings{
				Url:        "localhost:2990",
				User:       "admin",
				Name:       "my-jira",
				Type:       "jira",
				ProjectKey: "PK",
				IssueType:  "IssueType",
				Priority:   "Priority",
				Assignee:   []string{"Assignee"},
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"Jira output with missed type",
			data.OutputSettings{
				Url:        "localhost:2990",
				User:       "admin",
				Name:       "my-jira",
				ProjectKey: "PK",
				IssueType:  "IssueType",
				Priority:   "Priority",
				Assignee:   []string{"Assignee"},
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"Jira Output with some default values",
			data.OutputSettings{
				Url:        "localhost:2990",
				Name:       "my-jira-with-defaults",
				Type:       "jira",
				User:       "admin",
				Password:   "admin",
				ProjectKey: "PK",
				IssueType:  "",
				Priority:   "",
			},
			map[string]interface{}{
				"Url":        "localhost:2990",
				"User":       "admin",
				"Password":   "admin",
				"ProjectKey": "PK",
				"Issuetype":  IssueTypeDefault,
				"Priority":   PriorityDefault,
				"Assignee":   []string{"admin"},
			},
			false,
			"*outputs.JiraAPI",
		},
		{
			"Simple webhook output",
			data.OutputSettings{
				Url:  "http://localhost:8080",
				Name: "my-webhook",
				Type: "webhook",
			},
			map[string]interface{}{
				"Url": "http://localhost:8080",
			},
			false,
			"*outputs.WebhookOutput",
		},
		{
			"Simple ServiceNow output",
			data.OutputSettings{
				Name:         "my-servicenow",
				Type:         "serviceNow",
				User:         "admin",
				Password:     "secret",
				InstanceName: "dev108148",
				BoardName:    "incindent",
			},
			map[string]interface{}{
				"User":     "admin",
				"Password": "secret",
				"Instance": "dev108148",
				"Table":    "incindent",
			},
			false,
			"*outputs.ServiceNowOutput",
		},
		{
			"Simple Teams output",
			data.OutputSettings{
				Url:  "https://outlook.office.com/webhook/ABCD",
				Name: "my-teams",
				Type: "teams",
			},
			map[string]interface{}{
				"Webhook": "https://outlook.office.com/webhook/ABCD",
			},
			false,
			"*outputs.TeamsOutput",
		},
		{
			"HTTP Action output, with a timeout & body specified",
			data.OutputSettings{
				Method:   "GET",
				Timeout:  "10s",
				Url:      "https://foo.bar.com",
				Name:     "my-http-output",
				Type:     "http",
				BodyFile: "goldens/test.txt",
			},
			map[string]interface{}{
				"Name":   "HTTP Output",
				"Method": "GET",
				"Body":   "foo bar baz",
			},
			false,
			"*outputs.HTTPClient",
		},
		{
			"HTTP Action output, with no method specified",
			data.OutputSettings{
				Url:  "https://foo.bar.com",
				Name: "my-http-output",
				Type: "http",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"HTTP Action output, with invalid url specified",
			data.OutputSettings{
				Method: "get",
				Url:    "http://[fe80::1%en0]/",
				Name:   "my-http-output",
				Type:   "http",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"HTTP Action output, with invalid body file specified",
			data.OutputSettings{
				Method:   "GET",
				Url:      "https://foo.bar.com",
				Name:     "my-http-output",
				Type:     "http",
				BodyFile: "no such body file",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"HTTP Action output, with a invalid timeout",
			data.OutputSettings{
				Method:  "GET",
				Timeout: "ten seconds",
				Type:    "http",
			},
			map[string]interface{}{}, true,
			"<nil>",
		},
		{"Exec Action output",
			data.OutputSettings{
				Name:      "my-exec-output",
				Env:       []string{"foo=bar"},
				InputFile: "goldens/test.txt",
				Type:      "exec",
			},
			map[string]interface{}{
				"Name":      "Exec Output",
				"InputFile": "goldens/test.txt",
			},
			false,
			"*outputs.ExecClient",
		},
	}
	for _, test := range tests {
		o, err := buildAndInitOtpt(&test.outputSettings, "")

		if !test.shouldFail && err != nil {
			t.Fatalf("Unexpected error %v", err)
		}

		if test.shouldFail && o != nil && err != nil {
			t.Fatalf("No output expected for %s test case but was %s", test.caseDesc, o)
		} else if !test.shouldFail && o == nil {
			t.Fatalf("Not expected output returned for %s test case", test.caseDesc)
		}

		actualOutputCls := fmt.Sprintf("%T", o)
		if actualOutputCls != test.expectedOutputClass {
			t.Errorf("[%s] Incorrect output type, expected %s, got %s", test.caseDesc, test.expectedOutputClass, actualOutputCls)
		}

		for key, prop := range test.expctdProps {
			t.Logf("key %s\n", key)
			r := reflect.ValueOf(o)
			v := reflect.Indirect(r).FieldByName(key)
			if !v.IsValid() {
				t.Errorf("Property %s is not found", key)
				continue
			}
			mbStringSlice, ok := prop.([]string)
			if ok {
				vSlice, ok := v.Interface().([]string)
				if !ok {
					t.Errorf("Invalid type of property %s, expected []string, got %T", key, v.Interface())
				}

				if len(mbStringSlice) == len(vSlice) {
					for i := range mbStringSlice {
						if mbStringSlice[i] != vSlice[i] {
							t.Errorf("Invalid property %s, expected: %q, got: %q",
								key, mbStringSlice[i], vSlice[i])
						}
					}
				} else {
					t.Errorf("Wrong size of %s, expected: %d, got: %d", key, len(mbStringSlice), len(vSlice))
				}

			} else {
				if v.Interface() != prop {
					t.Errorf("Invalid property %s, expected %s, got %s", key, prop, v)
				}

			}
		}

	}
}
