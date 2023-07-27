package router

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildAndInitOtpt(t *testing.T) {
	tests := []struct {
		caseDesc            string
		actionSettings      ActionSettings
		expctdProps         map[string]interface{}
		shouldFail          bool
		expectedActionClass string
	}{
		{
			"Default Stdout Action",
			ActionSettings{
				Name:   "stdout",
				Type:   "stdout",
				Enable: true,
			},
			map[string]interface{}{
				"Name": "stdout",
			},
			false,
			"*actions.StdoutAction",
		},
		{
			"Simple Slack",
			ActionSettings{
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
			"*actions.SlackAction",
		},
		{
			"Simple Email action",
			ActionSettings{
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
			"*actions.EmailAction",
		},
		{
			"Simple Nexus IQ action",
			ActionSettings{
				Url:            "http://localhost:8070",
				User:           "admin",
				Password:       "admin123",
				Name:           "my-nexus",
				Type:           "nexusIq",
				OrganizationId: "222de33e8005408a844c12eab952c9b0",
			},
			map[string]interface{}{
				"Url":            "http://localhost:8070",
				"User":           "admin",
				"Password":       "admin123",
				"OrganizationId": "222de33e8005408a844c12eab952c9b0",
			},
			false,
			"*actions.NexusIqAction",
		},
		{
			"Simple Dependency Track action",
			ActionSettings{
				Url:                   "http://localhost:8080",
				Name:                  "my-dependencytrack",
				Type:                  "dependencytrack",
				DependencyTrackAPIKey: "api-key",
			},
			map[string]interface{}{
				"Url":    "http://localhost:8080",
				"APIKey": "api-key",
			},
			false,
			"*actions.DependencyTrackAction",
		},
		{
			"Simple Jira action",
			ActionSettings{
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
			"*actions.JiraAPI",
		},
		{
			"Jira action without credentials",
			ActionSettings{
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
			"Jira action without password",
			ActionSettings{
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
			"Jira action with missed type",
			ActionSettings{
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
			"Jira Action with some default values",
			ActionSettings{
				Url:        "localhost:2990",
				Name:       "my-jira-with-defaults",
				Type:       "jira",
				User:       "admin",
				Password:   "admin",
				ProjectKey: "PK",
			},
			map[string]interface{}{
				"Url":        "localhost:2990",
				"User":       "admin",
				"Password":   "admin",
				"ProjectKey": "PK",
				"Assignee":   []string{"admin"},
			},
			false,
			"*actions.JiraAPI",
		},
		{
			"Simple webhook action",
			ActionSettings{
				Url:  "http://localhost:8080",
				Name: "my-webhook",
				Type: "webhook",
			},
			map[string]interface{}{
				"Url": "http://localhost:8080",
			},
			false,
			"*actions.WebhookAction",
		},
		{
			"Simple ServiceNow action",
			ActionSettings{
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
			"*actions.ServiceNowAction",
		},
		{
			"ServiceNow action without BoardName",
			ActionSettings{
				Name:         "my-servicenow",
				Type:         "serviceNow",
				User:         "admin",
				Password:     "secret",
				InstanceName: "dev108148",
			},
			map[string]interface{}{
				"User":     "admin",
				"Password": "secret",
				"Instance": "dev108148",
				"Table":    ServiceNowTableDefault,
			},
			false,
			"*actions.ServiceNowAction",
		},
		{
			"Simple Teams action",
			ActionSettings{
				Url:  "https://outlook.office.com/webhook/ABCD",
				Name: "my-teams",
				Type: "teams",
			},
			map[string]interface{}{
				"Webhook": "https://outlook.office.com/webhook/ABCD",
			},
			false,
			"*actions.TeamsAction",
		},
		{
			"Simple Splunk action",
			ActionSettings{
				Url:   "http://localhost:8088",
				Name:  "my-splunk",
				Type:  "splunk",
				Token: "test_token_for_splunk",
			},
			map[string]interface{}{
				"Url":   "http://localhost:8088",
				"Name":  "my-splunk",
				"Token": "test_token_for_splunk",
			},
			false,
			"*actions.SplunkAction",
		},
		{
			"HTTP Action action, with a timeout & body file specified",
			ActionSettings{
				Method:   "POST",
				Timeout:  "10s",
				Url:      "https://foo.bar.com",
				Name:     "my-http-action",
				Type:     "http",
				BodyFile: "goldens/test.txt",
			},
			map[string]interface{}{
				"Name":     "my-http-action",
				"Method":   "POST",
				"BodyFile": "goldens/test.txt",
			},
			false,
			"*actions.HTTPClient",
		},
		{
			"HTTP Action action, with a timeout & body content specified",
			ActionSettings{
				Method:      "POST",
				Timeout:     "10s",
				Url:         "https://foo.bar.com",
				Name:        "my-http-action",
				Type:        "http",
				BodyContent: "foo bar baz body",
			},
			map[string]interface{}{
				"Name":        "my-http-action",
				"Method":      "POST",
				"BodyContent": "foo bar baz body",
			},
			false,
			"*actions.HTTPClient",
		},
		{
			"HTTP Action action, with a timeout & both body content and file specified",
			ActionSettings{
				Method:      "POST",
				Timeout:     "10s",
				Url:         "https://foo.bar.com",
				Name:        "my-http-action",
				Type:        "http",
				BodyFile:    "goldens/test.txt",
				BodyContent: "foo bar baz body",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"HTTP Action action, with no method specified",
			ActionSettings{
				Url:  "https://foo.bar.com",
				Name: "my-http-action",
				Type: "http",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"HTTP Action action, with invalid url specified",
			ActionSettings{
				Method: "get",
				Url:    "http://[fe80::1%en0]/",
				Name:   "my-http-action",
				Type:   "http",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"HTTP Action action, with a invalid timeout",
			ActionSettings{
				Method:  "GET",
				Timeout: "ten seconds",
				Type:    "http",
			},
			map[string]interface{}{}, true,
			"<nil>",
		},
		{"Exec Action action, with input-file config",
			ActionSettings{
				Name:      "my-exec-action",
				Env:       []string{"foo=bar"},
				InputFile: "goldens/test.txt",
				Type:      "exec",
			},
			map[string]interface{}{
				"Name":      "my-exec-action",
				"InputFile": "goldens/test.txt",
			},
			false,
			"*actions.ExecClient",
		},
		{"Exec Action action, with exec-script config",
			ActionSettings{
				Name: "my-exec-action",
				Env:  []string{"foo=bar"},
				ExecScript: `#!/bin/sh
echo "foo bar"`,
				Type: "exec",
			},
			map[string]interface{}{
				"Name": "my-exec-action",
				"ExecScript": `#!/bin/sh
echo "foo bar"`,
			},
			false,
			"*actions.ExecClient",
		},
		{"Exec Action action, with invalid config (both file and script)",
			ActionSettings{
				Name:      "my-exec-action",
				Env:       []string{"foo=bar"},
				InputFile: "goldens/test.txt",
				ExecScript: `#!/bin/sh
echo "foo bar"`,
				Type: "exec",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{"Exec Action action, with invalid config (no file nor script)",
			ActionSettings{
				Name: "my-exec-output",
				Env:  []string{"foo=bar"},
				Type: "exec",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"Kubernetes Action, happy path",
			ActionSettings{
				Name:              "my-k8s-output",
				Type:              "kubernetes",
				KubeNamespace:     "default",
				KubeConfigFile:    "goldens/kube-config.sample",
				KubeLabelSelector: "app=foobar",
				KubeActions: map[string]map[string]string{
					"labels":      {"foo-label": "bar-value"},
					"annotations": {"foo-annotation": "bar-value"},
				},
			},
			map[string]interface{}{
				"Name":              "my-k8s-output",
				"KubeNamespace":     "default",
				"KubeConfigFile":    "goldens/kube-config.sample",
				"KubeLabelSelector": "app=foobar",
				"KubeActions": map[string]map[string]string{
					"labels":      {"foo-label": "bar-value"},
					"annotations": {"foo-annotation": "bar-value"},
				},
			},
			false,
			"*actions.KubernetesClient",
		},
		{
			"Kubernetes Action, sad path, no kube-config",
			ActionSettings{
				Name:              "my-k8s-output",
				Type:              "kubernetes",
				KubeNamespace:     "default",
				KubeLabelSelector: "app=foobar",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
		{
			"Kubernetes Action, sad path, no kube namespace",
			ActionSettings{
				Name:              "my-k8s-output",
				Type:              "kubernetes",
				KubeConfigFile:    "goldens/kube-config.sample",
				KubeLabelSelector: "app=foobar",
			},
			map[string]interface{}{},
			true,
			"<nil>",
		},
	}
	for _, test := range tests {
		t.Run(test.caseDesc, func(t *testing.T) {
			o := BuildAndInitOtpt(&test.actionSettings, "")
			if test.shouldFail && o != nil {
				t.Fatalf("No output expected for %s test case but was %s", test.caseDesc, o)
			} else if !test.shouldFail && o == nil {
				t.Fatalf("Not expected output returned for %s test case", test.caseDesc)
			}
			actualActionCls := fmt.Sprintf("%T", o)
			if actualActionCls != test.expectedActionClass {
				t.Errorf("[%s] Incorrect output type, expected %s, got %s", test.caseDesc, test.expectedActionClass, actualActionCls)
			}

			for key, prop := range test.expctdProps {
				//t.Logf("key %s\n", key)
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
					assert.EqualValues(t, prop, v.Interface())
				}
			}
		})
	}
}
