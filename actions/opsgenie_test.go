package actions

import (
	"testing"

	"github.com/opsgenie/opsgenie-go-sdk-v2/alert"
	"github.com/stretchr/testify/assert"
)

func TestGetUserResponders(t *testing.T) {
	tests := []struct {
		name       string
		users      []string
		responders []alert.Responder
	}{
		{
			name:  "good way",
			users: []string{"user1", "user2"},
			responders: []alert.Responder{
				{Type: alert.UserResponder, Username: "user1"},
				{Type: alert.UserResponder, Username: "user2"},
			},
		},
		{
			name: "without users",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := getUserResponders(test.users)
			assert.Equal(t, test.responders, got)
		})
	}
}

func TestConvertResultToOpsGenie(t *testing.T) {
	tests := []struct {
		name   string
		title  string
		data   map[string]interface{}
		result *alert.CreateAlertRequest
	}{
		{
			name:  "good way",
			title: "all-in-one:3.5.19223",
			data: map[string]interface{}{
				"description": "all-in-one:3.5.19223 vulnerability scan report",
				"alias":       "all-in-one:3.5.19223",
				"entity":      "entity",
				"priority":    "P4",
				"tags":        []string{"tag1", "tag2"},
			},
			result: &alert.CreateAlertRequest{
				Message:     "all-in-one:3.5.19223",
				Priority:    alert.P4,
				Description: "all-in-one:3.5.19223 vulnerability scan report",
				Alias:       "all-in-one:3.5.19223",
				Entity:      "entity",
				Tags:        []string{"tag1", "tag2"},
			},
		},
		{
			name:  "only title",
			title: "all-in-one:3.5.19223",
			data:  map[string]interface{}{},
			result: &alert.CreateAlertRequest{
				Message:  "all-in-one:3.5.19223",
				Priority: alert.P3,
			},
		},
		{
			name:  "good way with tags as string",
			title: "all-in-one:3.5.19223",
			data: map[string]interface{}{
				"description": "all-in-one:3.5.19223 vulnerability scan report",
				"alias":       "all-in-one:3.5.19223",
				"entity":      "entity",
				"priority":    "P4",
				"tags":        "tag1,tag2",
			},
			result: &alert.CreateAlertRequest{
				Message:     "all-in-one:3.5.19223",
				Priority:    alert.P4,
				Description: "all-in-one:3.5.19223 vulnerability scan report",
				Alias:       "all-in-one:3.5.19223",
				Entity:      "entity",
				Tags:        []string{"tag1", "tag2"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ops := &OpsGenieAction{
				APIKey: "anyAPIkey",
			}
			err := ops.Init()
			assert.NoError(t, err)
			r := ops.convertResultToOpsGenie(test.title, test.data)
			assert.Equal(t, test.result, r)
		})
	}
}
