package outputs

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/go-jira"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

var metaIssuetype = &jira.MetaIssueType{Name: "Task", Fields: map[string]interface{}{
	"issuetype": map[string]interface{}{
		"name": "Issue Type",
		"schema": map[string]interface{}{
			"type": "issuetype",
		},
	},
	"project": map[string]interface{}{
		"name": "Project",
		"schema": map[string]interface{}{
			"type": "project",
		},
	},
	"priority": map[string]interface{}{
		"name": "Priority",
		"schema": map[string]interface{}{
			"type": "priority",
		},
	},
	"description": map[string]interface{}{
		"name": "Description",
		"schema": map[string]interface{}{
			"type": "string",
		},
	},
	"summary": map[string]interface{}{
		"name": "Summary",
		"schema": map[string]interface{}{
			"type": "string",
		},
	},
	"assignee": map[string]interface{}{
		"name": "Assignee",
		"schema": map[string]interface{}{
			"type": "user",
		},
	},
	"customfield_10020": map[string]interface{}{
		"name": "Sprint",
		"schema": map[string]interface{}{
			"type":  "array",
			"items": "json",
		},
	},
	"customfield_10021": map[string]interface{}{
		"name": "Flagged",
		"schema": map[string]interface{}{
			"type":  "array",
			"items": "option",
		},
	},
	"components": map[string]interface{}{
		"name": "Components",
		"schema": map[string]interface{}{
			"type":  "array",
			"items": "component",
		},
	},
	"versions": map[string]interface{}{
		"name": "Affects versions",
		"schema": map[string]interface{}{
			"type":  "array",
			"items": "version",
		},
	},
	"customfield_10015": map[string]interface{}{
		"name": "Start date",
		"schema": map[string]interface{}{
			"type": "date",
		},
	},
	"customfield_10009": map[string]interface{}{
		"name": "Actual end",
		"schema": map[string]interface{}{
			"type": "datetime",
		},
	},
	"customfield_10001": map[string]interface{}{
		"name": "Team",
		"schema": map[string]interface{}{
			"type": "any",
		},
	},
	"customfield_10004": map[string]interface{}{
		"name": "Impact",
		"schema": map[string]interface{}{
			"type": "option",
		},
	},
	"timespent": map[string]interface{}{
		"name": "Time Spent",
		"schema": map[string]interface{}{
			"type": "number",
		},
	},
	"customfield_10052": map[string]interface{}{
		"name":   "No schema type",
		"schema": map[string]interface{}{},
	},
	"customfield_10053": map[string]interface{}{
		"name": "No schema items",
		"schema": map[string]interface{}{
			"type": "array",
		},
	},
	"customfield_10054": map[string]interface{}{
		"name": "Bad Type",
		"schema": map[string]interface{}{
			"type": "badType",
		},
	},
}}

var fieldList = &[]jira.Field{
	{ID: "issuetype", Name: "Issue Type"},
	{ID: "project", Name: "Project"},
	{ID: "priority", Name: "Priority"},
	{ID: "description", Name: "Description"},
	{ID: "summary", Name: "Summary"},
}

func TestJiraAPI_GetName(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		jiraApi := &JiraAPI{Name: "testName"}
		name := jiraApi.GetName()

		assert.Equal(t, jiraApi.Name, name)
	})
}

func TestJiraAPI_FetchBoardId(t *testing.T) {
	tests := []struct {
		name        string
		boardName   string
		boardList   *jira.BoardsList
		wantJiraApi *JiraAPI
		wantError   string
	}{
		{
			name:        "happy path (0 boards found)",
			boardName:   "board0",
			boardList:   &jira.BoardsList{Values: []jira.Board{{Name: "board1"}, {Name: "board2"}}},
			wantJiraApi: &JiraAPI{BoardName: "board0"},
		},
		{
			name:        "happy path (1 board found)",
			boardName:   "board1",
			boardList:   &jira.BoardsList{Values: []jira.Board{{Name: "board1", ID: 1, Type: "Scrum"}, {Name: "board2", ID: 2, Type: "Scrum"}}},
			wantJiraApi: &JiraAPI{boardId: 1, BoardName: "board1", boardType: "Scrum"},
		},
		{
			name:        "happy path (2 boards found)",
			boardName:   "board2",
			boardList:   &jira.BoardsList{Values: []jira.Board{{Name: "board2", ID: 1, Type: "Scrum"}, {Name: "board2", ID: 2, Type: "Scrum"}}},
			wantJiraApi: &JiraAPI{boardId: 2, BoardName: "board2", boardType: "Scrum"},
		},
		{
			name:        "sad path (Failed to create client)",
			boardName:   "board3",
			wantJiraApi: &JiraAPI{BoardName: "board3"},
			wantError:   "Failed to create client",
		},
		{
			name:        "sad path (Failed to get boardList)",
			boardName:   "board4",
			wantJiraApi: &JiraAPI{BoardName: "board4"},
			wantError:   "Failed to get boardList",
		},
	}

	oldCreateClient := createClient
	defer func() { createClient = savedCreateClient }()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.boardList, test.wantError)))
			defer ts.Close()

			createClient = func(ctx *JiraAPI) (*jira.Client, error) {
				if test.wantError == "Failed to create client" {
					return nil, fmt.Errorf(test.wantError)
				} else {
					return jira.NewClient(ts.Client(), ts.URL)
				}
			}

			jiraApi := &JiraAPI{BoardName: test.boardName}
			jiraApi.fetchBoardId(test.boardName)

			assert.Equal(t, test.wantJiraApi, jiraApi)
		})
	}
}

func TestJiraAPI_FetchSprintId(t *testing.T) {
	tests := []struct {
		name         string
		sprints      *jira.SprintsList
		wantSprintId int
	}{
		{
			name:         "happy path (2 sprints found)",
			sprints:      &jira.SprintsList{Values: []jira.Sprint{{Name: "sprint0"}, {Name: "sprint1"}}},
			wantSprintId: 1,
		},
		{
			name:         "happy path (1 sprint found)",
			sprints:      &jira.SprintsList{Values: []jira.Sprint{{Name: "sprint32", ID: 32}}},
			wantSprintId: 32,
		},
		{
			name:         "happy path (0 sprints found)",
			sprints:      &jira.SprintsList{Values: []jira.Sprint{}},
			wantSprintId: NotConfiguredSprintId,
		},
		{
			name:         "sad path (Failed to get all sprints)",
			wantSprintId: NotConfiguredSprintId,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.sprints, "")))
			defer ts.Close()

			jiraApi := &JiraAPI{SprintId: -1}
			client, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			jiraApi.fetchSprintId(client)

			assert.Equal(t, test.wantSprintId, jiraApi.SprintId)
		})
	}
}

func TestJiraAPI_InitIssue(t *testing.T) {
	metaProject := &jira.MetaProject{
		Id:   "project ID",
		Name: "project name",
	}
	tests := []struct {
		name            string
		useSrvApi       bool
		httpStatus      int
		user            []*jira.User
		fieldsConfig    map[string]string
		wantIssueFields *jira.IssueFields
		wantError       string
	}{
		{
			name:       "happy path",
			useSrvApi:  true,
			httpStatus: http.StatusOK,
			user:       []*jira.User{{Name: "User"}},
			fieldsConfig: map[string]string{
				"Issue Type":       "Task",
				"Project":          "Project",
				"Priority":         "High",
				"Description":      "Description",
				"Summary":          "Summary",
				"Assignee":         "Assignee",
				"Sprint":           "1",
				"Flagged":          "Flagged",
				"Components":       "Components",
				"Affects versions": "1.0.1",
				"Start date":       "01.01.2022",
				"Actual end":       "01.01.2222",
				"Team":             "Team",
				"Impact":           "Impact",
				"Time Spent":       "10",
			},
			wantIssueFields: &jira.IssueFields{Unknowns: map[string]interface{}{
				"issuetype": jira.IssueType{Name: "Task"},
				"project": jira.Project{
					Name: "project name",
					ID:   "project ID",
				},
				"priority":          jira.Priority{Name: "High"},
				"assignee":          jira.User{Name: "User"},
				"description":       "Description",
				"summary":           "Summary",
				"customfield_10020": 1,
				"customfield_10021": []map[string]string{{"value": "Flagged"}},
				"components":        []jira.Component{{Name: "Components"}},
				"versions":          []string{"1.0.1"},
				"customfield_10015": "01.01.2022",
				"customfield_10009": "01.01.2222",
				"customfield_10001": "Team",
				"customfield_10004": jira.Option{Value: "Impact"},
				"timespent":         10,
			}},
		},
		{
			name:       "happy path (useSrvApi = false)",
			useSrvApi:  false,
			httpStatus: http.StatusOK,
			user:       []*jira.User{{Name: "User"}},
			fieldsConfig: map[string]string{
				"Assignee": "Assignee",
			},
			wantIssueFields: &jira.IssueFields{Unknowns: map[string]interface{}{
				"assignee": jira.User{Name: "User"},
			}},
		},
		{
			name:       "happy path (find user returns error)",
			httpStatus: http.StatusOK,
			fieldsConfig: map[string]string{
				"Assignee": "Assignee",
			},
			wantIssueFields: &jira.IssueFields{Unknowns: map[string]interface{}{}},
		},
		{
			name:       "happy path (users not found)",
			httpStatus: http.StatusOK,
			user:       []*jira.User{},
			fieldsConfig: map[string]string{
				"Assignee": "Assignee",
			},
			wantIssueFields: &jira.IssueFields{Unknowns: map[string]interface{}{}},
		},
		{
			name:         "sad path (bad field in fieldsConfig)",
			fieldsConfig: map[string]string{"Bad-field": "bad-field"},
			wantError:    "key Bad-field is not found in the list of fields",
		},
		{
			name:         "sad path (field doesn't have schema/type)",
			fieldsConfig: map[string]string{"No schema type": "No schema type"},
			wantError:    "\"customfield_10052/schema/type\" is not set",
		},
		{
			name:         "sad path (field doesn't have schema/items)",
			fieldsConfig: map[string]string{"No schema items": "No schema items"},
			wantError:    "\"customfield_10053/schema/items\" is not set",
		},
		{
			name:         "sad path (sprint is not a number)",
			fieldsConfig: map[string]string{"Sprint": "one"},
			wantError:    "strconv.Atoi: parsing \"one\": invalid syntax",
		},
		{
			name:         "sad path (number field is not a number)",
			fieldsConfig: map[string]string{"Time Spent": "two"},
			wantError:    "strconv.Atoi: parsing \"two\": invalid syntax",
		},
		{
			name:         "sad path (bad field type)",
			fieldsConfig: map[string]string{"Bad Type": "Bad Type"},
			wantError:    "Unknown issue type encountered",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.user, test.wantError)))
			defer ts.Close()

			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			issue, err := InitIssue(jiraClient, metaProject, metaIssuetype, test.fieldsConfig, test.useSrvApi)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				assert.Equal(t, test.wantIssueFields, issue.Fields)
			}
		})
	}
}

func TestJiraAPI_GetLayoutProvider(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		jiraApi := &JiraAPI{}
		wantLayoutProviderType := new(formatting.JiraLayoutProvider)
		LayoutProvider := jiraApi.GetLayoutProvider()
		assert.Equal(t, reflect.TypeOf(wantLayoutProviderType), reflect.TypeOf(LayoutProvider))
	})
}

func TestJiraAPI_BuildTransportClient(t *testing.T) {
	tests := []struct {
		name          string
		jiraApi       *JiraAPI
		wantTransport interface{}
		wantError     string
	}{
		{
			name:          "happy path bearer auth",
			jiraApi:       &JiraAPI{Token: "token", Password: "password"},
			wantTransport: &jira.BearerTokenAuthTransport{},
		},
		{
			name:          "happy path bearer auth",
			jiraApi:       &JiraAPI{User: "User", Password: "Password"},
			wantTransport: &jira.BasicAuthTransport{},
		},
		{
			name:      "sad path bearer auth for server jira",
			jiraApi:   &JiraAPI{Token: "token", Url: "https://johndoe.atlassian.net"},
			wantError: "Jira Cloud can't work with PAT",
		},
		{
			name:      "sad path bearer auth with bad url",
			jiraApi:   &JiraAPI{Token: "token", Url: "https://  johndoe.atlassian.net"},
			wantError: "Jira Cloud can't work with PAT",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := test.jiraApi.buildTransportClient()

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				assert.Equal(t, reflect.TypeOf(test.wantTransport), reflect.TypeOf(client.Transport))
			}
		})
	}
}

func TestJiraApi_createClient(t *testing.T) {
	tests := []struct {
		name      string
		jiraApi   *JiraAPI
		wantError string
	}{
		{
			name:    "happy path",
			jiraApi: &JiraAPI{},
		},
		{
			name:      "sad path (using PAT for cloud jira)",
			jiraApi:   &JiraAPI{Token: "token", Url: "https://johndoe.atlassian.net"},
			wantError: "Jira Cloud can't work with PAT",
		},
		{
			name:      "sad path (bad url)",
			jiraApi:   &JiraAPI{Url: "https://johndoe   .atlassian.net"},
			wantError: "unable to create new JIRA client",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := createClient(test.jiraApi)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestJiraAPI_Send(t *testing.T) {
	tests := []struct {
		name           string
		jiraApi        *JiraAPI
		createMetaInfo *jira.CreateMetaInfo
		fieldList      *[]jira.Field
		priorityList   *[]jira.Priority
		issue          *jira.Issue
		content        map[string]string
		wantError      string
	}{
		{
			name: "happy path",
			jiraApi: &JiraAPI{
				ProjectKey:      "project",
				User:            "user",
				boardType:       "scrum",
				Labels:          []string{"label1", "label2"},
				FixVersions:     []string{"fix1", "fix2"},
				AffectsVersions: []string{"affect1", "affect2"},
			},
			createMetaInfo: &jira.CreateMetaInfo{Projects: []*jira.MetaProject{{Key: "project", IssueTypes: []*jira.MetaIssueType{metaIssuetype}}}},
			fieldList:      fieldList,
			priorityList:   &[]jira.Priority{{Name: "High"}},
			issue:          &jira.Issue{},
			content:        map[string]string{"title": "title_content", "description": "description_content"},
		},
		{
			name:      "sad path (Failed to create client)",
			wantError: "Failed to create client",
		},
		{
			name:      "sad path (Failed to create meta project)",
			jiraApi:   &JiraAPI{},
			wantError: "Failed to create meta project",
		},
		{
			name:           "sad path (Failed to get issuetype)",
			jiraApi:        &JiraAPI{Issuetype: "Bug", ProjectKey: "project"},
			createMetaInfo: &jira.CreateMetaInfo{Projects: []*jira.MetaProject{{Key: "project", IssueTypes: []*jira.MetaIssueType{metaIssuetype}}}},
			wantError:      "Failed to get issuetype",
		},
		{
			name:           "sad path (Failed to create fields config)",
			jiraApi:        &JiraAPI{ProjectKey: "project"},
			createMetaInfo: &jira.CreateMetaInfo{Projects: []*jira.MetaProject{{Key: "project", IssueTypes: []*jira.MetaIssueType{metaIssuetype}}}},
			wantError:      "Failed to create fields config",
		},
		{
			name:           "sad path (Failed to init issue)",
			jiraApi:        &JiraAPI{ProjectKey: "project", Unknowns: map[string]string{"bad field": "bad field"}},
			createMetaInfo: &jira.CreateMetaInfo{Projects: []*jira.MetaProject{{Key: "project", IssueTypes: []*jira.MetaIssueType{metaIssuetype}}}},
			fieldList:      fieldList,
			priorityList:   &[]jira.Priority{{Name: "High"}},
			wantError:      "key bad field is not found in the list of fields",
		},
		{
			name:           "sad path (Failed to open issue)",
			jiraApi:        &JiraAPI{ProjectKey: "project"},
			createMetaInfo: &jira.CreateMetaInfo{Projects: []*jira.MetaProject{{Key: "project", IssueTypes: []*jira.MetaIssueType{metaIssuetype}}}},
			fieldList:      fieldList,
			priorityList:   &[]jira.Priority{{Name: "High"}},
			wantError:      "Failed to open issue",
		},
	}

	savedCreateClient := createClient
	defer func() { createClient = savedCreateClient }()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/rest/api/2/issue/createmeta", buildHttpHandler(test.createMetaInfo, test.wantError))
			mux.HandleFunc("/rest/api/2/field", buildHttpHandler(test.fieldList, test.wantError))
			mux.HandleFunc("/rest/api/2/priority", buildHttpHandler(test.priorityList, test.wantError))
			mux.HandleFunc("/rest/api/2/issue", buildHttpHandler(test.issue, test.wantError))
			ts := httptest.NewServer(mux)
			defer ts.Close()

			createClient = func(ctx *JiraAPI) (*jira.Client, error) {
				if test.wantError == "Failed to create client" {
					return nil, fmt.Errorf(test.wantError)
				} else {
					return jira.NewClient(ts.Client(), ts.URL)
				}
			}

			err := test.jiraApi.Send(test.content)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestJiraAPI_OpenIssue(t *testing.T) {
	tests := []struct {
		name      string
		issue     *jira.Issue
		wantError string
	}{
		{
			name:  "Happy path",
			issue: &jira.Issue{ID: "issue1"},
		},
		{
			name:      "sad path",
			wantError: "open issue error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.issue, test.wantError)))
			defer ts.Close()

			jiraApi := &JiraAPI{}
			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			issue, err := jiraApi.openIssue(jiraClient, test.issue)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				assert.Equal(t, test.issue, issue)
			}
		})
	}
}

func TestJiraAPI_CreateMetaProject(t *testing.T) {
	tests := []struct {
		name               string
		metaInfo           *jira.CreateMetaInfo
		wantMetaProjectKey string
		wantError          string
	}{
		{
			name: "happy path",
			metaInfo: &jira.CreateMetaInfo{
				Projects: []*jira.MetaProject{
					{Key: "test"},
					{Key: "debug"},
				},
			},
			wantMetaProjectKey: "debug",
		},
		{
			name:      "sad path (jira return error)",
			wantError: "failed to get create meta",
		},
		{
			name: "sad path (project not found)",
			metaInfo: &jira.CreateMetaInfo{
				Projects: []*jira.MetaProject{
					{Key: "test"},
					{Key: "debug"},
				},
			},
			wantMetaProjectKey: "non-existent-project",
			wantError:          "could not find project with key non-existent-project",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.metaInfo, test.wantError)))
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

func TestJiraAPI_CreateIssueType(t *testing.T) {
	tests := []struct {
		name          string
		jiraAPI       *JiraAPI
		metaProject   *jira.MetaProject
		wantIssueType string
		wantError     string
	}{
		{
			name:          "happy path (empty issueType, jira has 'Task' field)",
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
			wantError:   "project \"\" doesn't have issueType \"Bug\"",
		},
		{
			name:        "bad path (metaIssueType has empty IssueTypes)",
			jiraAPI:     &JiraAPI{Priority: ""},
			metaProject: &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{}},
			wantError:   "project \"\" doesn't have issueTypes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issueType, err := getIssueType(test.jiraAPI, test.metaProject)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Equal(t, test.wantIssueType, issueType)
			}
		})
	}
}

func TestJiraAPI_GetIssuePriority(t *testing.T) {
	tests := []struct {
		name         string
		jiraAPI      *JiraAPI
		priorities   []*jira.Priority
		wantPriority string
		wantError    string
	}{
		{
			name:         "happy path (empty priority, jira has 'High' field)",
			jiraAPI:      &JiraAPI{Priority: ""},
			priorities:   []*jira.Priority{{Name: "Highest"}, {Name: "High"}, {Name: "Medium"}},
			wantPriority: "High",
		},
		{
			name:         "happy path (empty priority, jira doesn't have 'High' field)",
			jiraAPI:      &JiraAPI{Priority: ""},
			priorities:   []*jira.Priority{{Name: "Highest"}, {Name: "Low"}, {Name: "Medium"}},
			wantPriority: "Highest",
		},
		{
			name:         "happy path (fill priority, jira has 'Medium' field)",
			jiraAPI:      &JiraAPI{Priority: "Medium"},
			priorities:   []*jira.Priority{{Name: "Highest"}, {Name: "High"}, {Name: "Medium"}},
			wantPriority: "Medium",
		},
		{
			name:       "bad path (fill priority, jira doesn't have 'Medium' field)",
			jiraAPI:    &JiraAPI{Priority: "Medium"},
			priorities: []*jira.Priority{{Name: "Highest"}, {Name: "High"}, {Name: "Low"}},
			wantError:  "project doesn't have issue priority \"Medium\"",
		},
		{
			name:       "bad path (jira returns empty priorities)",
			jiraAPI:    &JiraAPI{Priority: ""},
			priorities: []*jira.Priority{},
			wantError:  "project doesn't have issue priorities",
		},
		{
			name:      "bad path (jira returns error)",
			jiraAPI:   &JiraAPI{Priority: ""},
			wantError: "json: cannot unmarshal object into Go value of type []jira.Priority",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.priorities, test.wantError)))
			defer ts.Close()

			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			priority, err := getIssuePriority(test.jiraAPI, jiraClient)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.Equal(t, test.wantPriority, priority)
			}
		})
	}
}

func TestJiraAPI_CreateFieldsConfig(t *testing.T) {
	tests := []struct {
		name             string
		fields           []*jira.Field
		jiraApi          *JiraAPI
		content          *map[string]string
		wantFieldsConfig map[string]string
		wantError        string
	}{
		{
			name: "happy path (default field names)",
			fields: []*jira.Field{
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
			fields: []*jira.Field{
				{ID: "issuetype", Name: "Custom Issue Type"},
				{ID: "project", Name: "Custom Project"},
				{ID: "priority", Name: "Custom Priority"},
				{ID: "assignee", Name: "Custom Assignee"},
				{ID: "description", Name: "Custom Description"},
				{ID: "summary", Name: "Custom Summary"},
				{ID: "customfield_10020", Name: "Custom Sprint", Schema: jira.FieldSchema{Custom: defaultSprintPlugin}},
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
				"Custom Sprint":      "432",
			},
		},
		{
			name: "happy path (custom fields)",
			fields: []*jira.Field{
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
			wantError: "json: cannot unmarshal string into Go value of type []jira.Field",
		},
		{
			name:      "sad path (createIssuePriority return error)",
			fields:    []*jira.Field{},
			jiraApi:   &JiraAPI{},
			wantError: "project doesn't have issue priorities",
		},
	}

	savedGetIssuePriority := getIssuePriority
	defer func() { getIssuePriority = savedGetIssuePriority }()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(buildHttpHandler(test.fields, test.wantError)))
			defer ts.Close()

			jiraClient, err := jira.NewClient(ts.Client(), ts.URL)
			if err != nil {
				t.Fatalf("can't create jiraClient %v", err)
			}

			getIssuePriority = func(ctx *JiraAPI, client *jira.Client) (string, error) {
				if test.wantError != "" {
					return "", fmt.Errorf(test.wantError)
				} else {
					return test.jiraApi.Priority, nil
				}
			}

			fieldsConfig, err := createFieldsConfig(test.jiraApi, jiraClient, test.content)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				assert.Equal(t, test.wantFieldsConfig, fieldsConfig)
			}
		})
	}
}

func TestJiraAPI_CreateMetaIssueType(t *testing.T) {
	tests := []struct {
		name              string
		metaProject       *jira.MetaProject
		issueType         string
		wantMetaIssueType *jira.MetaIssueType
		wantError         string
	}{
		{
			name:              "happy path",
			metaProject:       &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{{Name: "Task"}, {Name: "Bug"}}},
			wantMetaIssueType: &jira.MetaIssueType{Name: "Task"},
		},
		{
			name:        "sad path",
			metaProject: &jira.MetaProject{IssueTypes: []*jira.MetaIssueType{{Name: "SubTask"}, {Name: "Bug"}}},
			wantError:   "could not find issuetype",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metaIssueType, err := createMetaIssueType(test.metaProject, defaultIssueType)

			if test.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				assert.Equal(t, test.wantMetaIssueType, metaIssueType)
			}
		})
	}
}

func TestJiraAPI_Init(t *testing.T) {
	tests := []struct {
		name        string
		jiraApi     *JiraAPI
		envPassword string
		wantJiraApi *JiraAPI
	}{
		{
			name:        "happy path",
			jiraApi:     &JiraAPI{BoardName: "board0", ProjectKey: "project", Password: "password"},
			wantJiraApi: &JiraAPI{BoardName: "board0", ProjectKey: "project", Password: "password"},
		},
		{
			name:        "happy path (empty BoardName)",
			jiraApi:     &JiraAPI{ProjectKey: "project", Password: "password"},
			wantJiraApi: &JiraAPI{BoardName: "project board", ProjectKey: "project", Password: "password"},
		},
		{
			name:        "happy path(empty password)",
			jiraApi:     &JiraAPI{BoardName: "board0", ProjectKey: "project"},
			envPassword: "test_password",
			wantJiraApi: &JiraAPI{BoardName: "board0", ProjectKey: "project", Password: "test_password"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.envPassword != "" {
				savedJiraPassword := os.Getenv("JIRA_PASSWORD")
				_ = os.Setenv("JIRA_PASSWORD", test.envPassword)
				defer func() {
					_ = os.Setenv("JIRA_PASSWORD", savedJiraPassword)
				}()
			}

			_ = test.jiraApi.Init()

			assert.Equal(t, test.wantJiraApi, test.jiraApi)
		})
	}
}

func buildHttpHandler(successResponse interface{}, errorResponse string) func(w http.ResponseWriter, r *http.Request) {
	if !reflect.ValueOf(successResponse).IsNil() { // successResponse always has type therefore != nil (https://go.dev/doc/faq#nil_error)
		return func(w http.ResponseWriter, r *http.Request) {
			fieldListJson, _ := json.Marshal(successResponse)
			_, _ = w.Write(fieldListJson)
		}
	} else {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			if errorResponse != "" {
				_, _ = w.Write([]byte(errorResponse))
			}
		}
	}
}
