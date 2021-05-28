package alertmgr

import (
	"testing"

	"github.com/aquasecurity/postee/outputs"
)

var (
	slack_cfg = `
- name: my-slack
  type: slack
  enable: false
  url: "https://hooks.slack.com/services/TT/BBB/WWWW"
`
)

func TestBuildSlackOutput(t *testing.T) {
	tests := []struct {
		outputSettings OutputSettings
		slack          outputs.SlackOutput
	}{
		{
			OutputSettings{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/TT/BBB/WWWW",
			},
			outputs.SlackOutput{
				Url:  "https://hooks.slack.com/services/TT/BBB/WWWW",
				Name: "my-slack",
			},
		},
	}

	for _, test := range tests {
		r := buildSlackOutput(&test.outputSettings, "aqua.demo")
		if r.Url != test.slack.Url {
			t.Errorf("Wrong url for Slack output\nWaited: %q\nResult: %q", test.slack.Url, r.Url)
		}
	}
}

func TestBuildEmailOutput(t *testing.T) {
	tests := []struct {
		outputSettings OutputSettings
		email          outputs.EmailOutput
	}{
		{
			OutputSettings{
				User:       "EmailUser",
				Password:   "pAsSw0rD",
				Host:       "smtp.gmail.com",
				Port:       "587",
				Sender:     "google@gmail.com",
				Recipients: []string{"r1@gmail.com"},
			},
			outputs.EmailOutput{
				User:       "EmailUser",
				Password:   "pAsSw0rD",
				Host:       "smtp.gmail.com",
				Port:       "587",
				Sender:     "google@gmail.com",
				Recipients: []string{"r1@gmail.com"},
			},
		},
	}

	for _, test := range tests {
		r := buildEmailOutput(&test.outputSettings)
		if r.User != test.email.User {
			t.Errorf("Wrong setting of User:\nWaited: %q\nResult: %q", test.email.User, r.User)
		}
		if r.Password != test.email.Password {
			t.Errorf("Wrong setting of Password:\nWaited: %q\nResult: %q", test.email.Password, r.Password)
		}
		if r.Host != test.email.Host {
			t.Errorf("Wrong setting of Host:\nWaited: %q\nResult: %q", test.email.Host, r.Host)
		}
		if r.Port != test.email.Port {
			t.Errorf("Wrong setting of Port:\nWaited: %q\nResult: %q", test.email.Port, r.Port)
		}
		if r.Sender != test.email.Sender {
			t.Errorf("Wrong setting of Sender:\nWaited: %q\nResult: %q", test.email.Sender, r.Sender)
		}
		if len(r.Recipients) == len(test.email.Recipients) {
			for i := range r.Recipients {
				if r.Recipients[i] != test.email.Recipients[i] {
					t.Errorf("Wrong recipients :\nWaited: %q\nResult: %q",
						test.email.Recipients[i], r.Recipients[i])
				}
			}
		} else {
			t.Errorf("Wrong size of Recipients:\nWaited: %d\nResult: %d", len(test.email.Recipients), len(r.Recipients))
		}
	}
}

func TestBuildJiraOutput(t *testing.T) {
	tests := []struct {
		outputSettings OutputSettings
		jira           outputs.JiraAPI
	}{
		{
			outputSettings: OutputSettings{
				Url:        "localhost:2990",
				User:       "admin",
				Password:   "admin",
				ProjectKey: "PK",
				IssueType:  "IssueType",
				Priority:   "Priority",
				Assignee:   []string{"Assignee"},
			},
			jira: outputs.JiraAPI{
				Url:        "localhost:2990",
				User:       "admin",
				Password:   "admin",
				ProjectKey: "PK",
				Issuetype:  "IssueType",
				Priority:   "Priority",
				Assignee:   []string{"Assignee"},
			},
		},
		{
			outputSettings: OutputSettings{
				Url:        "localhost:2990",
				User:       "admin",
				Password:   "admin",
				ProjectKey: "PK",
				IssueType:  "",
				Priority:   "",
			},
			jira: outputs.JiraAPI{
				Url:        "localhost:2990",
				User:       "admin",
				Password:   "admin",
				ProjectKey: "PK",
				Issuetype:  IssueTypeDefault,
				Priority:   PriorityDefault,
				Assignee:   []string{"admin"},
			},
		},
	}

	for _, test := range tests {
		r := buildJiraOutput(&test.outputSettings)
		if r.Url != test.jira.Url {
			t.Errorf("Wrong URL:\nWaited: %q\nResult: %q", test.jira.Url, r.Url)
		}
		if r.User != test.jira.User {
			t.Errorf("Wrong User:\nWaited: %q\nResult: %q", test.jira.User, r.User)
		}
		if r.Password != test.jira.Password {
			t.Errorf("Wrong Password:\nWaited: %q\nResult: %q", test.jira.Password, r.Password)
		}
		if r.ProjectKey != test.jira.ProjectKey {
			t.Errorf("Wrong ProjectKey:\nWaited: %q\nResult: %q", test.jira.ProjectKey, r.ProjectKey)
		}
		if r.Issuetype != test.jira.Issuetype {
			t.Errorf("Wrong Issuetype:\nWaited: %q\nResult: %q", test.jira.Issuetype, r.Issuetype)
		}
		if r.Priority != test.jira.Priority {
			t.Errorf("Wrong Priority:\nWaited: %q\nResult: %q", test.jira.Priority, r.Priority)
		}
		/*
			if r.Assignee != test.jira.Assignee {
				t.Errorf("Wrong Assignee:\nWaited: %q\nResult: %q", test.jira.Assignee, r.Assignee)
			}
		*/
	}
}
