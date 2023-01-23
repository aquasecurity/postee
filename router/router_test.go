package router

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSelectRepositoryTemplateByResourceTypeKey(t *testing.T) {
	tests := []struct {
		name       string
		msg        map[string]interface{}
		outputType string
		want       string
	}{
		{
			name:       "select iac-jira template",
			msg:        map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType: "jira",
			want:       "iac-jira",
		},
		{
			name:       "select iac-servicenow template",
			msg:        map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType: "serviceNow",
			want:       "iac-servicenow",
		},
		{
			name:       "select iac-slack template",
			msg:        map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType: "slack",
			want:       "iac-slack",
		},
		{
			name:       "select iac-html template for email",
			msg:        map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType: "email",
			want:       "iac-html",
		},
		{
			name:       "select iac-html template for teams",
			msg:        map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType: "teams",
			want:       "iac-html",
		},
		{
			name:       "wrong resourceTypeKey",
			msg:        map[string]interface{}{"resourceTypeKey": "wrong"},
			outputType: "serviceNow",
			want:       "",
		},
		{
			name:       "select unsupported template",
			msg:        map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType: "splunk",
			want:       "raw-message-json",
		},
		{
			name:       "Select template without 'resourceTypeKey' field",
			msg:        map[string]interface{}{},
			outputType: "serviceNow",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTemplate := selectRepositoryTemplateByResourceTypeKey(tt.msg, tt.outputType)
			assert.Equal(t, tt.want, gotTemplate)
		})
	}
}
