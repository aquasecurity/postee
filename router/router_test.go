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
			name:       "Select image servicenow",
			msg:        map[string]interface{}{"custom_trigger_type": "custom-scan_result"},
			outputType: "serviceNow",
			want:       "vuls-servicenow",
		},
		{
			name:       "Select insight servicenow",
			msg:        map[string]interface{}{"custom_trigger_type": "custom-insight"},
			outputType: "serviceNow",
			want:       "insight-servicenow",
		},
		{
			name:       "Select incident servicenow",
			msg:        map[string]interface{}{"custom_trigger_type": "custom-incident"},
			outputType: "serviceNow",
			want:       "incident-servicenow",
		},
		{
			name:       "Select iac servicenow",
			msg:        map[string]interface{}{"custom_trigger_type": "custom-iac"},
			outputType: "serviceNow",
			want:       "iac-servicenow",
		},
		{
			name:       "Select insight jira",
			msg:        map[string]interface{}{"custom_trigger_type": "custom-insight"},
			outputType: "jira",
			want:       "insight-jira",
		},
		{
			name:       "Select template without 'custom_trigger_type' field",
			msg:        map[string]interface{}{},
			outputType: "serviceNow",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTemplate := chooseTemplateByCustomTriggerType(tt.msg, tt.outputType)
			assert.Equal(t, tt.want, gotTemplate)
		})
	}

}
