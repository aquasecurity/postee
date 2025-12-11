package teams_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// AdaptiveCard represents the Microsoft Adaptive Card format
type AdaptiveCard struct {
	Type    string            `json:"type"`
	Schema  string            `json:"$schema"`
	Version string            `json:"version"`
	Body    []AdaptiveElement `json:"body"`
}

// AdaptiveElement represents an element in the Adaptive Card body
type AdaptiveElement struct {
	Type   string `json:"type"`
	Text   string `json:"text,omitempty"`
	Wrap   bool   `json:"wrap,omitempty"`
	Size   string `json:"size,omitempty"`
	Weight string `json:"weight,omitempty"`
	Color  string `json:"color,omitempty"`
}

// WorkflowsAttachment represents an attachment in the Workflows message
type WorkflowsAttachment struct {
	ContentType string       `json:"contentType"`
	ContentURL  *string      `json:"contentUrl"`
	Content     AdaptiveCard `json:"content"`
}

// WorkflowsMessage represents the message format for Teams Workflows webhook
type WorkflowsMessage struct {
	Type        string                `json:"type"`
	Attachments []WorkflowsAttachment `json:"attachments"`
}

// CreateWorkflowsMessage sends a message via Teams Workflows webhook using Adaptive Cards format
func CreateWorkflowsMessage(webhook, title, content string) error {
	// Build the Adaptive Card body elements
	bodyElements := []AdaptiveElement{
		{
			Type:   "TextBlock",
			Text:   title,
			Wrap:   true,
			Size:   "Large",
			Weight: "Bolder",
		},
		{
			Type: "TextBlock",
			Text: content,
			Wrap: true,
		},
	}

	// Create the Adaptive Card
	card := AdaptiveCard{
		Type:    "AdaptiveCard",
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Version: "1.4",
		Body:    bodyElements,
	}

	// Create the message with attachment
	message := WorkflowsMessage{
		Type: "message",
		Attachments: []WorkflowsAttachment{
			{
				ContentType: "application/vnd.microsoft.card.adaptive",
				ContentURL:  nil,
				Content:     card,
			},
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Send the request
	client := http.DefaultClient
	req, err := http.NewRequest("POST", webhook, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Teams Workflows returns 202 Accepted for successful requests
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("Teams Workflows Error: %q. Response: %s", resp.Status, string(body))
	}

	return nil
}

