package router

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSelectRepositoryTemplateByResourceTypeKey(t *testing.T) {
	tests := []struct {
		name         string
		msg          map[string]interface{}
		outputType   string
		templateName string
		want         string
	}{
		{
			name:         "Custom Fields Message template for email selects iac-custom-fields",
			msg:          map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType:   "email",
			templateName: "vuls-custom-fields-email",
			want:         "iac-custom-fields",
		},
		{
			name:         "Custom Fields Message template for teams selects iac-custom-fields",
			msg:          map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType:   "teams",
			templateName: "vuls-custom-fields-teams",
			want:         "iac-custom-fields",
		},
		{
			name:         "html template for email keeps iac-html",
			msg:          map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType:   "email",
			templateName: "vuls-html",
			want:         "iac-html",
		},
		{
			name:         "Custom Fields Message template for jira keeps iac-jira",
			msg:          map[string]interface{}{"resourceTypeKey": "code-repository"},
			outputType:   "jira",
			templateName: "vuls-custom-fields-email",
			want:         "iac-jira",
		},
		{
			name:         "Custom Fields Message template without code-repository key is not swapped",
			msg:          map[string]interface{}{},
			outputType:   "email",
			templateName: "vuls-custom-fields-email",
			want:         "",
		},
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
			gotTemplate := selectRepositoryTemplateByResourceTypeKey(tt.msg, tt.outputType, tt.templateName)
			assert.Equal(t, tt.want, gotTemplate)
		})
	}
}
