package router

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestChooseTemplateByCustomTriggerType(t *testing.T) {
	tests := []struct {
		name       string
		msg        map[string]interface{}
		outputType string
		want       string
	}{
		{
			name:       "happy path. Servicenow incident",
			msg:        map[string]interface{}{customTriggerTypeField: "custom-incident"},
			outputType: "serviceNow",
			want:       "incident-servicenow",
		},
		{
			name:       "happy path. Servicenow insight",
			msg:        map[string]interface{}{customTriggerTypeField: "custom-insight"},
			outputType: "serviceNow",
			want:       "insight-servicenow",
		},
		{
			name:       "happy path. Servicenow scan result",
			msg:        map[string]interface{}{customTriggerTypeField: "custom-scan_result"},
			outputType: "serviceNow",
			want:       "vuls-servicenow",
		},
		{
			name:       "happy path. Servicenow repository",
			msg:        map[string]interface{}{customTriggerTypeField: "custom-iac"},
			outputType: "serviceNow",
			want:       "iac-servicenow",
		},
		{
			name:       "happy path. Jira scan result",
			msg:        map[string]interface{}{customTriggerTypeField: "custom-scan_result"},
			outputType: "jira",
			want:       "",
		},
		{
			name:       "happy path. Msg doesn't contain customTriggerTypeField",
			msg:        map[string]interface{}{},
			outputType: "serviceNow",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := chooseTemplateByCustomTriggerType(tt.msg, tt.outputType)
			assert.Equal(t, tt.want, template)
		})
	}
}
