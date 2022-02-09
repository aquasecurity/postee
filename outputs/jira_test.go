package outputs

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/go-jira"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestСreateIssuePriority(t *testing.T) {
	tests := []struct {
		name         string
		jiraAPI      *JiraAPI
		priorities   interface{}
		wantPriority string
		wantError    string
	}{
		{
			name:         "happy path (empty priority, jira have 'High' field)",
			jiraAPI:      &JiraAPI{Priority: ""},
			priorities:   []jira.Priority{{Name: "Highest"}, {Name: "High"}, {Name: "Medium"}},
			wantPriority: "High",
		},
		{
			name:         "happy path (empty priority, jira doesn't have 'High' field)",
			jiraAPI:      &JiraAPI{Priority: ""},
			priorities:   []jira.Priority{{Name: "Highest"}, {Name: "Low"}, {Name: "Medium"}},
			wantPriority: "Highest",
		},
		{
			name:         "happy path (fill priority, jira have 'Medium' field)",
			jiraAPI:      &JiraAPI{Priority: "Medium"},
			priorities:   []jira.Priority{{Name: "Highest"}, {Name: "High"}, {Name: "Medium"}},
			wantPriority: "Medium",
		},
		{
			name:       "bad path (fill priority, jira doesn't have 'Medium' field)",
			jiraAPI:    &JiraAPI{Priority: "Medium"},
			priorities: []jira.Priority{{Name: "Highest"}, {Name: "High"}, {Name: "Low"}},
			wantError:  "project don't have issue priority \"Medium\"",
		},
		{
			name:       "bad path (jira returns empty priorities)",
			jiraAPI:    &JiraAPI{Priority: ""},
			priorities: nil,
			wantError:  "project don't have issue priorities",
		},
		{
			name:       "bad path (jira returns error)",
			jiraAPI:    &JiraAPI{Priority: ""},
			priorities: jira.Issue{},
			wantError:  "failed to get issue priority list: json: cannot unmarshal object into Go value of type []jira.Priority",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				propertiesJson, err := json.Marshal(test.priorities)
				if err != nil {
					t.Errorf("Unexpected json mashal error: %v", err)
				}
				_, err = w.Write(propertiesJson)
				if err != nil {
					t.Errorf("Unexpected write response error: %v", err)
				}
			}))
			defer ts.Close()

			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			err = createIssuePriority(test.jiraAPI, jiraClient)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Equal(t, test.wantPriority, test.jiraAPI.Priority)
			}
		})
	}
}

func TestCreateIssueType(t *testing.T) {
	tests := []struct {
		name          string
		jiraAPI       *JiraAPI
		metaProject   *jira.MetaProject
		wantIssueType string
		wantError     string
	}{
		{
			name:          "happy path (empty issueType, jira have 'Task' field)",
			jiraAPI:       &JiraAPI{},
			metaProject:   &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{{Name: "Task"}, {Name: "Bug"}}},
			wantIssueType: "Task",
		},
		{
			name:          "happy path (empty issueType, jira doesn't have 'Task' field)",
			jiraAPI:       &JiraAPI{},
			metaProject:   &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{{Name: "Story"}, {Name: "Bug"}}},
			wantIssueType: "Story",
		},
		{
			name:          "happy path (fill issueType, jira has 'Bug' field)",
			jiraAPI:       &JiraAPI{Issuetype: "Bug"},
			metaProject:   &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{{Name: "Task"}, {Name: "Bug"}}},
			wantIssueType: "Bug",
		},
		{
			name:        "bad path (fill issueType, jira doesn't have 'Bug' field)",
			jiraAPI:     &JiraAPI{Issuetype: "Bug"},
			metaProject: &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{{Name: "Task"}, {Name: "Story"}}},
			wantError:   "project \"\" don't have issueType \"Bug\"",
		},
		{
			name:        "bad path (metaIssueType have empty IssueTypes)",
			jiraAPI:     &JiraAPI{Priority: ""},
			metaProject: &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{}},
			wantError:   "project \"\" don't have issueTypes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := createIssueType(test.jiraAPI, test.metaProject)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Equal(t, test.wantIssueType, test.jiraAPI.Issuetype)
			}
		})
	}
}

func TestCreateMetaProject(t *testing.T) {
	tests := []struct {
		name               string
		metaInfo           interface{}
		wantMetaProjectKey string
		wantError          string
	}{
		{
			name: "happy path",
			metaInfo: jira.CreateMetaInfo{
				Projects: []*jira.MetaProject{
					{Key: "test"},
					{Key: "debug"},
				},
			},
			wantMetaProjectKey: "debug",
		},
		{
			name:      "sad path (jira return error)",
			metaInfo:  "bad struct",
			wantError: "failed to get create meta : json: cannot unmarshal string into Go value of type jira.CreateMetaInfo",
		},
		{
			name: "sad path (project not found)",
			metaInfo: jira.CreateMetaInfo{
				Projects: []*jira.MetaProject{
					{Key: "test"},
					{Key: "debug"},
				},
			},
			wantMetaProjectKey: "bad project",
			wantError:          "could not find project with key bad project",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				metaInfoJson, err := json.Marshal(test.metaInfo)
				if err != nil {
					t.Errorf("Unexpected marshal metaInfo error: %v", err)
				}
				_, err = w.Write(metaInfoJson)
				if err != nil {
					t.Errorf("Unexpected write response error: %v", err)
				}
			}))
			defer ts.Close()
			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			metaProject, err := createMetaProject(jiraClient, test.wantMetaProjectKey)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Equal(t, test.wantMetaProjectKey, metaProject.Key)
			}
		})
	}
}

func TestCreateFieldsConfig(t *testing.T) {
	tests := []struct {
		name             string
		fields           interface{}
		jiraApi          *JiraAPI
		content          *map[string]string
		wantFieldsConfig map[string]string
		wantError        string
	}{
		{
			name: "happy path (default field names)",
			fields: []jira.Field{
				{ID: "issuetype", Name: "Issue Type"},
				{ID: "project", Name: "Project"},
				{ID: "priority", Name: "Priority"},
				{ID: "assignee", Name: "Assignee"},
				{ID: "description", Name: "Description"},
				{ID: "summary", Name: "Summary"},
			},
			jiraApi: &JiraAPI{
				User:        "User",
				Issuetype:   "Task",
				ProjectKey:  "Project",
				Priority:    "High",
				Description: "Description",
				Summary:     "Summary",
			},
			content: &map[string]string{},
			wantFieldsConfig: map[string]string{
				"Issue Type":  "Task",
				"Project":     "Project",
				"Priority":    "High",
				"Assignee":    "User",
				"Description": "Description",
				"Summary":     "Summary",
			},
		},
		{
			name: "happy path (custom field names)",
			fields: []jira.Field{
				{ID: "issuetype", Name: "Custom Issue Type"},
				{ID: "project", Name: "Custom Project"},
				{ID: "priority", Name: "Custom Priority"},
				{ID: "assignee", Name: "Custom Assignee"},
				{ID: "description", Name: "Custom Description"},
				{ID: "summary", Name: "Custom Summary"},
			},
			jiraApi: &JiraAPI{
				User:        "User",
				Issuetype:   "Task",
				ProjectKey:  "Project",
				Priority:    "High",
				Description: "Description",
				Summary:     "Summary",
				SprintId:    432,
				Assignee:    []string{"Assignee"},
			},
			content: &map[string]string{"owners": "owners"},
			wantFieldsConfig: map[string]string{
				"Custom Issue Type":  "Task",
				"Custom Project":     "Project",
				"Custom Priority":    "High",
				"Custom Assignee":    "Assignee",
				"Custom Description": "Description",
				"Custom Summary":     "Summary",
				"Sprint":             "432",
			},
		},
		{
			name: "happy path (custom fields)",
			fields: []jira.Field{
				{ID: "issuetype", Name: "Issue Type"},
				{ID: "project", Name: "Project"},
				{ID: "priority", Name: "Priority"},
				{ID: "assignee", Name: "Assignee"},
				{ID: "description", Name: "Description"},
				{ID: "summary", Name: "Summary"},
			},
			jiraApi: &JiraAPI{
				User:        "User",
				Issuetype:   "Task",
				ProjectKey:  "Project",
				Priority:    "High",
				Description: "Description",
				Summary:     "Summary",
				Unknowns:    map[string]string{"Custom field": "Custom field value"},
			},
			content: &map[string]string{},
			wantFieldsConfig: map[string]string{
				"Issue Type":   "Task",
				"Project":      "Project",
				"Priority":     "High",
				"Assignee":     "User",
				"Description":  "Description",
				"Summary":      "Summary",
				"Custom field": "Custom field value",
			},
		},
		{
			name:      "sad path (filed.GetList() return error)",
			fields:    "bad fields array",
			wantError: "json: cannot unmarshal string into Go value of type []jira.Field",
		},
		{
			name:      "sad path (createIssuePriority return error)",
			fields:    []jira.Field{},
			jiraApi:   &JiraAPI{},
			wantError: "project don't have issue priorities",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fieldsJson, err := json.Marshal(test.fields)
				if err != nil {
					t.Errorf("Unexpected marshal metaInfo error: %v", err)
				}
				_, err = w.Write(fieldsJson)
				if err != nil {
					t.Errorf("Unexpected write response error: %v", err)
				}
			}))
			defer ts.Close()

			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			savedCreateIssuePriority := createIssuePriority
			createIssuePriority = func(ctx *JiraAPI, client *jira.Client) error {
				if test.wantError != "" {
					return fmt.Errorf(test.wantError)
				} else {
					return nil
				}
			}
			defer func() { createIssuePriority = savedCreateIssuePriority }()

			fieldsConfig, err := createFieldsConfig(test.jiraApi, jiraClient, test.content)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				for key, value := range test.wantFieldsConfig {
					if fieldsConfig[key] != value {
						t.Errorf("error fieldsConfig value, expected: %s, got: %s", value, fieldsConfig[key])
					}
				}
			}
		})
	}
}
