package teams_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/postee/v2/log"
)

// AdaptiveCard represents the Microsoft Adaptive Card format
type AdaptiveCard struct {
	Type    string        `json:"type"`
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Body    []interface{} `json:"body"`
	Actions []Action      `json:"actions,omitempty"`
}

// Action represents an action button in an Adaptive Card
type Action struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// TextBlock represents a text element in an Adaptive Card
type TextBlock struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Wrap      bool   `json:"wrap,omitempty"`
	Size      string `json:"size,omitempty"`
	Weight    string `json:"weight,omitempty"`
	Color     string `json:"color,omitempty"`
	Spacing   string `json:"spacing,omitempty"`
	Separator bool   `json:"separator,omitempty"`
}

// FactSet represents a set of key-value pairs
type FactSet struct {
	Type  string `json:"type"`
	Facts []Fact `json:"facts"`
}

// Fact represents a single key-value pair
type Fact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

// ColumnSet represents columns in an Adaptive Card
type ColumnSet struct {
	Type    string   `json:"type"`
	Columns []Column `json:"columns"`
}

// Column represents a single column
type Column struct {
	Type  string        `json:"type"`
	Width string        `json:"width"`
	Items []interface{} `json:"items"`
}

// Container represents a container in an Adaptive Card
type Container struct {
	Type  string        `json:"type"`
	Items []interface{} `json:"items"`
	Style string        `json:"style,omitempty"`
	Bleed bool          `json:"bleed,omitempty"`
}

// EventType identifies the type of event being processed
type EventType string

const (
	EventTypeScanResult = "custom-scan_result"
	EventTypeIncident   = "custom-incident"
	EventTypeInsight    = "custom-insight"
	EventTypeIssue      = "custom-issue"
)

// CreateWorkflowsMessage sends a message via Teams Workflows webhook using Adaptive Card format
func CreateWorkflowsMessage(webhook, title, content string) error {
	// Extract raw event data from the content
	rawData := extractRawEventData(content)

	// Build and send Adaptive Card
	card := buildAdaptiveCard(title, rawData)

	jsonData, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("failed to marshal card: %w", err)
	}

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

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("teams Workflows error: %q, response: %s", resp.Status, string(body))
	}

	return nil
}

// extractRawEventData extracts the raw event data from content
// It handles the case where content might be:
// 1. Raw JSON event data (from raw-message-json template)
// 2. Rego template processed output (wrapped in type: "message", attachments)
// 3. Plain text
func extractRawEventData(content string) string {
	// Try to parse as JSON first
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		// Not valid JSON, return as-is
		return content
	}

	// Check if this is a rego template wrapped message (type: "message" with attachments)
	if msgType, ok := data["type"].(string); ok && msgType == "message" {
		if attachments, ok := data["attachments"].([]interface{}); ok && len(attachments) > 0 {
			// This is a rego template output, try to extract the original input
			// The rego template might have embedded the original data somewhere
			// For now, we'll look for common fields that indicate raw event data
			if firstAttachment, ok := attachments[0].(map[string]interface{}); ok {
				if cardContent, ok := firstAttachment["content"].(map[string]interface{}); ok {
					// Check if there's body content we can use
					if body, ok := cardContent["body"].([]interface{}); ok && len(body) > 1 {
						// Try to find the text block with original JSON
						for _, item := range body {
							if block, ok := item.(map[string]interface{}); ok {
								if blockType, ok := block["type"].(string); ok && blockType == "TextBlock" {
									if text, ok := block["text"].(string); ok {
										// This might be JSON-stringified event data
										var rawData map[string]interface{}
										if err := json.Unmarshal([]byte(text), &rawData); err == nil {
											// Successfully parsed, this is the raw event data
											return text
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Check if this looks like raw event data by looking for common event fields
	if _, hasImage := data["image"]; hasImage {
		return content // This is raw event data
	}
	if _, hasInsight := data["insight"]; hasInsight {
		return content // This is raw event data
	}
	if _, hasCategory := data["category"]; hasCategory {
		if _, hasSeverity := data["severity_score"]; hasSeverity {
			return content // This is incident data
		}
	}
	if _, hasIssueDetails := data["issue_details"]; hasIssueDetails {
		return content // This is issue data
	}

	// Return as-is - might be some other format
	return content
}

// buildAdaptiveCard creates a formatted Adaptive Card from the input
func buildAdaptiveCard(title, content string) AdaptiveCard {
	card := AdaptiveCard{
		Type:    "AdaptiveCard",
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Version: "1.4",
		Body:    []interface{}{},
	}

	// Try to parse content as JSON for structured display
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(content), &data); err == nil {
		// Detect event type and build appropriate card
		eventType, _ := data["customTriggerType"].(string)
		if eventType == "" {
			// Fallback detection based on payload structure
			if _, hasIssueDetails := data["issue_details"]; hasIssueDetails {
				eventType = EventTypeIssue
			} else if _, hasInsight := data["insight"]; hasInsight {
				eventType = EventTypeInsight
			} else if _, hasSeverityScore := data["severity_score"]; hasSeverityScore {
				if _, hasType := data["type"]; hasType {
					eventType = EventTypeIncident
				}
			} else if _, hasImage := data["image"]; hasImage {
				eventType = EventTypeScanResult
			}
		}
		log.Logger.Debugf("AdaptiveCard event type: %s", eventType)
		switch eventType {
		case EventTypeScanResult:
			buildScanResultCard(&card, title, data)
		case EventTypeIncident:
			buildIncidentCard(&card, title, data)
		case EventTypeInsight:
			buildInsightCard(&card, title, data)
		case EventTypeIssue:
			buildIssueCard(&card, title, data)
		default:
			// Fall back to generic structured card
			buildGenericStructuredCard(&card, title, data)
		}
	} else {
		// Fallback to simple text display
		card.Body = append(card.Body, TextBlock{
			Type:   "TextBlock",
			Text:   title,
			Wrap:   true,
			Size:   "Large",
			Weight: "Bolder",
		})
		card.Body = append(card.Body, TextBlock{
			Type: "TextBlock",
			Text: content,
			Wrap: true,
		})
	}

	return card
}

// ============================================================
// SCAN RESULT CARD BUILDER
// ============================================================

func buildScanResultCard(card *AdaptiveCard, title string, data map[string]interface{}) {
	imageName := getString(data, "image")
	registry := getString(data, "registry")

	// Title
	cardTitle := "🔍 Aqua Security | Image Scan Report"
	if title != "" && title != "-" {
		cardTitle = title
	}
	card.Body = append(card.Body, TextBlock{
		Type:   "TextBlock",
		Text:   cardTitle,
		Wrap:   true,
		Size:   "Large",
		Weight: "Bolder",
	})

	// Image info facts
	facts := []Fact{
		{Title: "Image", Value: imageName},
		{Title: "Registry", Value: registry},
	}

	// Add digest if present
	if digest := getString(data, "digest"); digest != "" {
		shortDigest := digest
		if len(digest) > 20 {
			shortDigest = digest[:20] + "..."
		}
		facts = append(facts, Fact{Title: "Digest", Value: shortDigest})
	}

	// Check compliance status
	if assurance, ok := data["image_assurance_results"].(map[string]interface{}); ok {
		if disallowed, ok := assurance["disallowed"].(bool); ok && disallowed {
			facts = append(facts, Fact{Title: "Compliance", Value: "❌ **Non-compliant**"})
		} else {
			facts = append(facts, Fact{Title: "Compliance", Value: "✅ Compliant"})
		}
	}

	// Malware and sensitive data
	if vulnSummary, ok := data["vulnerability_summary"].(map[string]interface{}); ok {
		if malware := getFloat(vulnSummary, "malware"); malware > 0 {
			facts = append(facts, Fact{Title: "Malware", Value: "⚠️ Yes"})
		} else {
			facts = append(facts, Fact{Title: "Malware", Value: "✅ No"})
		}
		if sensitive := getFloat(vulnSummary, "sensitive"); sensitive > 0 {
			facts = append(facts, Fact{Title: "Sensitive Data", Value: "⚠️ Yes"})
		} else {
			facts = append(facts, Fact{Title: "Sensitive Data", Value: "✅ No"})
		}
	}

	card.Body = append(card.Body, FactSet{
		Type:  "FactSet",
		Facts: facts,
	})

	// Vulnerability summary
	if vulnSummary, ok := data["vulnerability_summary"].(map[string]interface{}); ok {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**📊 Vulnerabilities Summary**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		vulnFacts := []Fact{}
		if critical := getFloat(vulnSummary, "critical"); true {
			vulnFacts = append(vulnFacts, Fact{Title: "🔴 Critical", Value: fmt.Sprintf("%d", int(critical))})
		}
		if high := getFloat(vulnSummary, "high"); true {
			vulnFacts = append(vulnFacts, Fact{Title: "🟠 High", Value: fmt.Sprintf("%d", int(high))})
		}
		if medium := getFloat(vulnSummary, "medium"); true {
			vulnFacts = append(vulnFacts, Fact{Title: "🟡 Medium", Value: fmt.Sprintf("%d", int(medium))})
		}
		if low := getFloat(vulnSummary, "low"); true {
			vulnFacts = append(vulnFacts, Fact{Title: "🟢 Low", Value: fmt.Sprintf("%d", int(low))})
		}
		if negligible := getFloat(vulnSummary, "negligible"); true {
			vulnFacts = append(vulnFacts, Fact{Title: "⚪ Negligible", Value: fmt.Sprintf("%d", int(negligible))})
		}

		card.Body = append(card.Body, FactSet{
			Type:  "FactSet",
			Facts: vulnFacts,
		})
	}

	// Assurance controls (limit to first 5)
	if assurance, ok := data["image_assurance_results"].(map[string]interface{}); ok {
		if checks, ok := assurance["checks_performed"].([]interface{}); ok && len(checks) > 0 {
			card.Body = append(card.Body, TextBlock{
				Type:      "TextBlock",
				Text:      "**🛡️ Assurance Controls**",
				Wrap:      true,
				Separator: true,
				Spacing:   "Medium",
			})

			maxChecks := len(checks)
			if maxChecks > 5 {
				maxChecks = 5
			}

			for i := 0; i < maxChecks; i++ {
				if c, ok := checks[i].(map[string]interface{}); ok {
					control := getString(c, "control")
					policyName := getString(c, "policy_name")
					failed, _ := c["failed"].(bool)

					status := "✅ PASS"
					if failed {
						status = "❌ FAIL"
					}

					card.Body = append(card.Body, TextBlock{
						Type: "TextBlock",
						Text: fmt.Sprintf("%d. **%s** | %s | %s", i+1, control, policyName, status),
						Wrap: true,
					})
				}
			}

			if len(checks) > 5 {
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("_...and %d more controls_", len(checks)-5),
					Wrap: true,
				})
			}
		}
	}

	// Response policy and scopes
	addResponsePolicyInfo(card, data)

	// Console URL
	if url := getString(data, "url"); url != "" {
		card.Body = append(card.Body, TextBlock{
			Type:    "TextBlock",
			Text:    fmt.Sprintf("🔗 [View in Aqua Console](%s)", url),
			Wrap:    true,
			Spacing: "Medium",
		})
	}
}

// ============================================================
// INCIDENT CARD BUILDER
// ============================================================

func buildIncidentCard(card *AdaptiveCard, title string, data map[string]interface{}) {
	name := getString(data, "name")
	category := getString(data, "category")
	// Server sends "type" not "main_category"
	mainCategory := getString(data, "type")
	severityScore := getFloat(data, "severity_score")
	severity := getString(data, "severity")

	// Determine severity color indicator
	severityEmoji := "🟡"
	score := int(severityScore)
	switch {
	case score >= 3:
		severityEmoji = "🔴" // Critical
	case score == 2:
		severityEmoji = "🟠" // High
	case score == 1:
		severityEmoji = "🟡" // Medium
	case score == 0:
		severityEmoji = "🟢" // Low
	}

	// Title
	cardTitle := fmt.Sprintf("%s Incident Detection", severityEmoji)
	if title != "" && title != "-" {
		cardTitle = title
	}
	card.Body = append(card.Body, TextBlock{
		Type:   "TextBlock",
		Text:   cardTitle,
		Wrap:   true,
		Size:   "Large",
		Weight: "Bolder",
	})

	// Severity badge
	severityText := strings.Title(severity)
	if severityText == "" {
		switch {
		case score >= 3:
			severityText = "Critical"
		case score == 2:
			severityText = "High"
		case score == 1:
			severityText = "Medium"
		default:
			severityText = "Low"
		}
	}
	card.Body = append(card.Body, TextBlock{
		Type:   "TextBlock",
		Text:   fmt.Sprintf("**Severity:** %s %s (Score: %.0f)", severityEmoji, severityText, severityScore),
		Wrap:   true,
		Weight: "Bolder",
	})

	// Incident Overview
	card.Body = append(card.Body, TextBlock{
		Type:      "TextBlock",
		Text:      "**📋 Incident Overview**",
		Wrap:      true,
		Separator: true,
		Spacing:   "Medium",
	})

	facts := []Fact{
		{Title: "Name", Value: name},
		{Title: "Category", Value: category},
	}

	if mainCategory != "" {
		facts = append(facts, Fact{Title: "Type", Value: strings.Title(mainCategory)})
	}

	// Server sends "host_name" not "host"
	if host := getString(data, "host_name"); host != "" {
		facts = append(facts, Fact{Title: "Host", Value: host})
	} else if host := getString(data, "host_id"); host != "" {
		facts = append(facts, Fact{Title: "Host ID", Value: host})
	}

	// Parse additional fields from nested "data" JSON
	var parsedDataFields map[string]interface{}
	if dataStr := getString(data, "data"); dataStr != "" {
		if err := json.Unmarshal([]byte(dataStr), &parsedDataFields); err != nil {
			log.Logger.Debugf("Failed to parse incident data JSON: %v", err)
		}
	}

	// Container, namespace, cluster from parsed data or root
	if container := getString(data, "container"); container != "" {
		facts = append(facts, Fact{Title: "Container", Value: container})
	} else if parsedDataFields != nil {
		if container := getString(parsedDataFields, "container"); container != "" {
			facts = append(facts, Fact{Title: "Container", Value: container})
		}
	}

	if namespace := getString(data, "namespace"); namespace != "" {
		facts = append(facts, Fact{Title: "Namespace", Value: namespace})
	} else if parsedDataFields != nil {
		if namespace := getString(parsedDataFields, "namespace"); namespace != "" {
			facts = append(facts, Fact{Title: "Namespace", Value: namespace})
		}
	}

	if cluster := getString(data, "cluster"); cluster != "" {
		facts = append(facts, Fact{Title: "Cluster", Value: cluster})
	} else if parsedDataFields != nil {
		// Server sends "k8s_cluster" in data JSON
		if cluster := getString(parsedDataFields, "k8s_cluster"); cluster != "" {
			facts = append(facts, Fact{Title: "Cluster", Value: cluster})
		}
	}

	if image := getString(data, "image"); image != "" {
		facts = append(facts, Fact{Title: "Image", Value: image})
	}

	// Server sends "create_time" not "timestamp"
	if ts := getFloat(data, "create_time"); ts > 0 {
		t := time.Unix(int64(ts), 0)
		facts = append(facts, Fact{Title: "Time", Value: t.Format("Jan 2, 2006 15:04:05")})
	} else if ts := getFloat(data, "timestamp"); ts > 0 {
		t := time.Unix(int64(ts), 0)
		facts = append(facts, Fact{Title: "Time", Value: t.Format("Jan 2, 2006 15:04:05")})
	}

	card.Body = append(card.Body, FactSet{
		Type:  "FactSet",
		Facts: facts,
	})

	// Parse and display incident data details
	if parsedDataFields != nil {
		buildIncidentDataSection(card, mainCategory, parsedDataFields)
	} else if dataStr := getString(data, "data"); dataStr != "" {
		// Display raw data if not JSON
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**📝 Details**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})
		card.Body = append(card.Body, TextBlock{
			Type: "TextBlock",
			Text: dataStr,
			Wrap: true,
		})
	}

	// Response policy and scopes
	addResponsePolicyInfo(card, data)

	// Console URL
	if url := getString(data, "url"); url != "" {
		card.Body = append(card.Body, TextBlock{
			Type:    "TextBlock",
			Text:    fmt.Sprintf("🔗 [View in Aqua Console](%s)", url),
			Wrap:    true,
			Spacing: "Medium",
		})
	}
}

// buildIncidentDataSection builds the details section based on incident type
func buildIncidentDataSection(card *AdaptiveCard, mainCategory string, parsedData map[string]interface{}) {
	switch mainCategory {
	case "malware":
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**🦠 Malware Detection**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		facts := []Fact{}
		if malware := getString(parsedData, "malware"); malware != "" {
			facts = append(facts, Fact{Title: "Malware Name", Value: malware})
		}
		if malwareType := getString(parsedData, "malware_type"); malwareType != "" {
			facts = append(facts, Fact{Title: "Type", Value: malwareType})
		}
		if resource := getString(parsedData, "resource"); resource != "" {
			facts = append(facts, Fact{Title: "Resource", Value: resource})
		}
		if action := getString(parsedData, "action"); action != "" {
			facts = append(facts, Fact{Title: "Action", Value: action})
		}
		if tactic := getString(parsedData, "tactic"); tactic != "" {
			facts = append(facts, Fact{Title: "MITRE Tactic", Value: tactic})
		}
		if technique := getString(parsedData, "technique"); technique != "" {
			facts = append(facts, Fact{Title: "MITRE Technique", Value: technique})
		}

		if len(facts) > 0 {
			card.Body = append(card.Body, FactSet{
				Type:  "FactSet",
				Facts: facts,
			})
		}

	case "runtime":
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**⚡ Runtime Control**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		facts := []Fact{}
		if control := getString(parsedData, "control"); control != "" {
			facts = append(facts, Fact{Title: "Control", Value: control})
		}
		if rule := getString(parsedData, "rule"); rule != "" {
			facts = append(facts, Fact{Title: "Runtime Policy", Value: rule})
		}
		if level := getString(parsedData, "level"); level != "" {
			facts = append(facts, Fact{Title: "Action", Value: level})
		}
		if user := getString(parsedData, "user"); user != "" {
			facts = append(facts, Fact{Title: "User", Value: user})
		}
		if resource := getString(parsedData, "resource"); resource != "" {
			facts = append(facts, Fact{Title: "Process", Value: resource})
		}
		if tactic := getString(parsedData, "tactic"); tactic != "" {
			facts = append(facts, Fact{Title: "MITRE Tactic", Value: tactic})
		}
		if technique := getString(parsedData, "technique"); technique != "" {
			facts = append(facts, Fact{Title: "MITRE Technique", Value: technique})
		}

		if len(facts) > 0 {
			card.Body = append(card.Body, FactSet{
				Type:  "FactSet",
				Facts: facts,
			})
		}

	case "behavioral":
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**🔬 Behavioral Detection**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		facts := []Fact{}
		if user := getString(parsedData, "user"); user != "" {
			facts = append(facts, Fact{Title: "User", Value: user})
		}
		if process := getString(parsedData, "process"); process != "" {
			facts = append(facts, Fact{Title: "Process", Value: process})
		}
		if tactic := getString(parsedData, "tactic"); tactic != "" {
			facts = append(facts, Fact{Title: "MITRE Tactic", Value: tactic})
		}
		if technique := getString(parsedData, "technique"); technique != "" {
			facts = append(facts, Fact{Title: "MITRE Technique", Value: technique})
		}
		if desc := getString(parsedData, "signature_description"); desc != "" {
			facts = append(facts, Fact{Title: "Description", Value: desc})
		}

		if len(facts) > 0 {
			card.Body = append(card.Body, FactSet{
				Type:  "FactSet",
				Facts: facts,
			})
		}

	default:
		// Generic details section
		if len(parsedData) > 0 {
			card.Body = append(card.Body, TextBlock{
				Type:      "TextBlock",
				Text:      "**📝 Details**",
				Wrap:      true,
				Separator: true,
				Spacing:   "Medium",
			})

			facts := []Fact{}
			for key, value := range parsedData {
				if strVal, ok := value.(string); ok && strVal != "" {
					facts = append(facts, Fact{Title: strings.Title(key), Value: strVal})
				}
			}
			if len(facts) > 0 {
				card.Body = append(card.Body, FactSet{
					Type:  "FactSet",
					Facts: facts,
				})
			}
		}
	}
}

// ============================================================
// INSIGHT CARD BUILDER
// ============================================================

func buildInsightCard(card *AdaptiveCard, title string, data map[string]interface{}) {
	insight, _ := data["insight"].(map[string]interface{})
	resource, _ := data["resource"].(map[string]interface{})
	evidence, _ := data["evidence"].(map[string]interface{})

	insightID := getString(insight, "id")
	description := getString(insight, "description")
	impact := getString(insight, "impact")
	priority := getFloat(insight, "priority")

	resourceID := getString(resource, "id")
	resourceName := getString(resource, "name")
	resourceARN := getString(resource, "arn")

	// Determine severity
	severityText := "Low"
	severityEmoji := "🟢"
	switch int(priority) {
	case 0:
		severityText = "Critical"
		severityEmoji = "🔴"
	case 1:
		severityText = "High"
		severityEmoji = "🟠"
	case 2:
		severityText = "Medium"
		severityEmoji = "🟡"
	case 3:
		severityText = "Low"
		severityEmoji = "🟢"
	}

	// Title
	cardTitle := fmt.Sprintf("%s Cloud Insight | %s", severityEmoji, insightID)
	if title != "" && title != "-" {
		cardTitle = title
	}
	card.Body = append(card.Body, TextBlock{
		Type:   "TextBlock",
		Text:   cardTitle,
		Wrap:   true,
		Size:   "Large",
		Weight: "Bolder",
	})

	// Insight Details
	card.Body = append(card.Body, TextBlock{
		Type:      "TextBlock",
		Text:      "**💡 Insight Details**",
		Wrap:      true,
		Separator: true,
		Spacing:   "Medium",
	})

	insightFacts := []Fact{
		{Title: "ID", Value: insightID},
		{Title: "Severity", Value: fmt.Sprintf("%s %s", severityEmoji, severityText)},
	}

	if description != "" {
		insightFacts = append(insightFacts, Fact{Title: "Description", Value: description})
	}
	if impact != "" {
		insightFacts = append(insightFacts, Fact{Title: "Impact", Value: impact})
	}

	// Dates
	if foundDate := getString(resource, "found_date"); foundDate != "" {
		insightFacts = append(insightFacts, Fact{Title: "Found Date", Value: foundDate[:min(19, len(foundDate))]})
	}
	if lastScanned := getString(resource, "last_scanned"); lastScanned != "" {
		insightFacts = append(insightFacts, Fact{Title: "Last Scanned", Value: lastScanned[:min(19, len(lastScanned))]})
	}

	card.Body = append(card.Body, FactSet{
		Type:  "FactSet",
		Facts: insightFacts,
	})

	// Resource Details
	card.Body = append(card.Body, TextBlock{
		Type:      "TextBlock",
		Text:      "**☁️ Resource Details**",
		Wrap:      true,
		Separator: true,
		Spacing:   "Medium",
	})

	resourceFacts := []Fact{
		{Title: "Resource ID", Value: resourceID},
		{Title: "Resource Name", Value: resourceName},
	}
	if resourceARN != "" {
		resourceFacts = append(resourceFacts, Fact{Title: "ARN", Value: resourceARN})
	}

	card.Body = append(card.Body, FactSet{
		Type:  "FactSet",
		Facts: resourceFacts,
	})

	// Evidence section
	if evidence != nil {
		addEvidenceSection(card, evidence)
	}

	// Recommendation
	if rec := getRecommendation(evidence); rec != "" {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**💊 Recommendation**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})
		card.Body = append(card.Body, TextBlock{
			Type: "TextBlock",
			Text: rec,
			Wrap: true,
		})
	}

	// Response policy and scopes
	addResponsePolicyInfo(card, data)

	// Console URL
	if insightID != "" && resourceID != "" {
		url := fmt.Sprintf("https://cloud.aquasec.com/ah/#/insights/%s/resource/%s", insightID, resourceID)
		card.Body = append(card.Body, TextBlock{
			Type:    "TextBlock",
			Text:    fmt.Sprintf("🔗 [View in Aqua Console](%s)", url),
			Wrap:    true,
			Spacing: "Medium",
		})
	}
}

func addEvidenceSection(card *AdaptiveCard, evidence map[string]interface{}) {
	hasEvidence := false

	// Vulnerabilities
	if vulns, ok := evidence["vulnerabilities"].([]interface{}); ok && len(vulns) > 0 {
		hasEvidence = true
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**🔓 Vulnerabilities Evidence**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		maxVulns := len(vulns)
		if maxVulns > 5 {
			maxVulns = 5
		}

		for i := 0; i < maxVulns; i++ {
			if v, ok := vulns[i].(map[string]interface{}); ok {
				name := getString(v, "name")
				severity := getString(v, "severity")
				pkgName := getString(v, "package_name")
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("• **%s** | %s | %s", name, severity, pkgName),
					Wrap: true,
				})
			}
		}

		if len(vulns) > 5 {
			card.Body = append(card.Body, TextBlock{
				Type: "TextBlock",
				Text: fmt.Sprintf("_...and %d more vulnerabilities_", len(vulns)-5),
				Wrap: true,
			})
		}
	}

	// Malware
	if malware, ok := evidence["malware"].([]interface{}); ok && len(malware) > 0 {
		hasEvidence = true
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**🦠 Malware Evidence**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		for i, m := range malware {
			if i >= 5 {
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("_...and %d more_", len(malware)-5),
					Wrap: true,
				})
				break
			}
			if mal, ok := m.(map[string]interface{}); ok {
				fileName := getString(mal, "file_name")
				filePath := getString(mal, "file_path")
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("• **%s** | %s", fileName, filePath),
					Wrap: true,
				})
			}
		}
	}

	// Sensitive data
	if sensitive, ok := evidence["sensitive_data"].([]interface{}); ok && len(sensitive) > 0 {
		hasEvidence = true
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**🔐 Sensitive Data Evidence**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		for i, s := range sensitive {
			if i >= 5 {
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("_...and %d more_", len(sensitive)-5),
					Wrap: true,
				})
				break
			}
			if sens, ok := s.(map[string]interface{}); ok {
				fileType := getString(sens, "file_type")
				filePath := getString(sens, "file_path")
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("• **%s** | %s", fileType, filePath),
					Wrap: true,
				})
			}
		}
	}

	if !hasEvidence {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**📎 Evidence**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})
		card.Body = append(card.Body, TextBlock{
			Type: "TextBlock",
			Text: "_No detailed evidence available_",
			Wrap: true,
		})
	}
}

func getRecommendation(evidence map[string]interface{}) string {
	if evidence == nil {
		return ""
	}

	if rec := getString(evidence, "vulnerabilities_remediation"); rec != "" {
		return rec
	}
	if rec := getString(evidence, "sensitive_data_remediation"); rec != "" {
		return rec
	}
	if rec := getString(evidence, "malware_remediation"); rec != "" {
		return rec
	}
	return ""
}

// ============================================================
// ISSUE CARD BUILDER
// ============================================================

func buildIssueCard(card *AdaptiveCard, title string, data map[string]interface{}) {
	issueDetails, _ := data["issue_details"].(map[string]interface{})

	// Get issue info
	issueName := getString(issueDetails, "name")
	description := getString(issueDetails, "description")
	severity := getString(issueDetails, "severity")
	resourceType := getString(issueDetails, "resource_type")
	status := getString(issueDetails, "status")

	// Determine severity emoji
	severityEmoji := "🟡"
	switch severity {
	case "critical":
		severityEmoji = "🔴"
	case "high":
		severityEmoji = "🟠"
	case "medium":
		severityEmoji = "🟡"
	case "low":
		severityEmoji = "🟢"
	}

	// Title
	cardTitle := fmt.Sprintf("%s Security Issue | %s", severityEmoji, strings.Title(severity))
	if title != "" && title != "-" {
		cardTitle = title
	}
	card.Body = append(card.Body, TextBlock{
		Type:   "TextBlock",
		Text:   cardTitle,
		Wrap:   true,
		Size:   "Large",
		Weight: "Bolder",
	})

	// Issue Overview
	card.Body = append(card.Body, TextBlock{
		Type:      "TextBlock",
		Text:      "**📋 Issue Overview**",
		Wrap:      true,
		Separator: true,
		Spacing:   "Medium",
	})

	facts := []Fact{
		{Title: "Name", Value: issueName},
		{Title: "Severity", Value: fmt.Sprintf("%s %s", severityEmoji, strings.Title(severity))},
		{Title: "Status", Value: status},
		{Title: "Resource Type", Value: resourceType},
	}

	card.Body = append(card.Body, FactSet{
		Type:  "FactSet",
		Facts: facts,
	})

	// Description
	if description != "" {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**📝 Description**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})
		card.Body = append(card.Body, TextBlock{
			Type: "TextBlock",
			Text: description,
			Wrap: true,
		})
	}

	// Environment details
	if env, ok := issueDetails["environment"].([]interface{}); ok && len(env) > 0 {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**🌐 Environment**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		envFacts := []Fact{}
		for _, e := range env {
			if item, ok := e.(map[string]interface{}); ok {
				key := getString(item, "key")
				value := getString(item, "value")
				if key != "" && value != "" {
					envFacts = append(envFacts, Fact{Title: key, Value: value})
				}
			}
		}
		if len(envFacts) > 0 {
			card.Body = append(card.Body, FactSet{
				Type:  "FactSet",
				Facts: envFacts,
			})
		}
	}

	// Affected Resources
	if affected, ok := issueDetails["affected_resources"].([]interface{}); ok && len(affected) > 0 {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      fmt.Sprintf("**⚠️ Affected Resources (%d)**", len(affected)),
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		maxResources := len(affected)
		if maxResources > 5 {
			maxResources = 5
		}
		for i := 0; i < maxResources; i++ {
			if name, ok := affected[i].(string); ok {
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("• %s", name),
					Wrap: true,
				})
			}
		}
		if len(affected) > 5 {
			card.Body = append(card.Body, TextBlock{
				Type: "TextBlock",
				Text: fmt.Sprintf("_...and %d more_", len(affected)-5),
				Wrap: true,
			})
		}
	}

	// Vulnerabilities from vulnerabilities_list
	if vulnList, ok := data["vulnerabilities_list"].(map[string]interface{}); ok {
		if vulns, ok := vulnList["result"].([]interface{}); ok && len(vulns) > 0 {
			card.Body = append(card.Body, TextBlock{
				Type:      "TextBlock",
				Text:      fmt.Sprintf("**🔓 Vulnerabilities (%d)**", len(vulns)),
				Wrap:      true,
				Separator: true,
				Spacing:   "Medium",
			})

			maxVulns := len(vulns)
			if maxVulns > 5 {
				maxVulns = 5
			}
			for i := 0; i < maxVulns; i++ {
				if v, ok := vulns[i].(map[string]interface{}); ok {
					cveName := getString(v, "name")
					vulnSeverity := getString(v, "aqua_severity")
					fixVersion := getString(v, "fix_version")

					resource, _ := v["resource"].(map[string]interface{})
					pkgName := getString(resource, "name")

					text := fmt.Sprintf("• **%s** | %s | %s", cveName, vulnSeverity, pkgName)
					if fixVersion != "" {
						text += fmt.Sprintf(" | Fix: %s", fixVersion)
					}
					card.Body = append(card.Body, TextBlock{
						Type: "TextBlock",
						Text: text,
						Wrap: true,
					})
				}
			}
			if len(vulns) > 5 {
				card.Body = append(card.Body, TextBlock{
					Type: "TextBlock",
					Text: fmt.Sprintf("_...and %d more vulnerabilities_", len(vulns)-5),
					Wrap: true,
				})
			}
		}
	}

	// Response policy info
	addResponsePolicyInfo(card, data)
}

// ============================================================
// GENERIC CARD BUILDER (FALLBACK)
// ============================================================

func buildGenericStructuredCard(card *AdaptiveCard, title string, data map[string]interface{}) {
	// Title
	cardTitle := "Aqua Security Notification"
	if title != "" && title != "-" {
		cardTitle = title
	}
	card.Body = append(card.Body, TextBlock{
		Type:   "TextBlock",
		Text:   cardTitle,
		Wrap:   true,
		Size:   "Large",
		Weight: "Bolder",
	})

	// Build facts from top-level string/number fields
	facts := []Fact{}
	for key, value := range data {
		switch v := value.(type) {
		case string:
			if v != "" && len(v) < 200 {
				facts = append(facts, Fact{Title: strings.Title(key), Value: v})
			}
		case float64:
			facts = append(facts, Fact{Title: strings.Title(key), Value: fmt.Sprintf("%v", v)})
		case bool:
			facts = append(facts, Fact{Title: strings.Title(key), Value: fmt.Sprintf("%v", v)})
		}
	}

	if len(facts) > 0 {
		// Limit to 15 facts max
		if len(facts) > 15 {
			facts = facts[:15]
		}
		card.Body = append(card.Body, FactSet{
			Type:  "FactSet",
			Facts: facts,
		})
	}

	// Response policy and scopes
	addResponsePolicyInfo(card, data)

	// URL if present
	if url := getString(data, "url"); url != "" {
		card.Body = append(card.Body, TextBlock{
			Type:    "TextBlock",
			Text:    fmt.Sprintf("🔗 [View Details](%s)", url),
			Wrap:    true,
			Spacing: "Medium",
		})
	}
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

func addResponsePolicyInfo(card *AdaptiveCard, data map[string]interface{}) {
	policyName := getString(data, "response_policy_name")
	scopes := getStringArray(data, "application_scope")

	if policyName != "" || len(scopes) > 0 {
		card.Body = append(card.Body, TextBlock{
			Type:      "TextBlock",
			Text:      "**📌 Response Policy**",
			Wrap:      true,
			Separator: true,
			Spacing:   "Medium",
		})

		policyFacts := []Fact{}
		if policyName != "" {
			policyFacts = append(policyFacts, Fact{Title: "Policy Name", Value: policyName})
		}
		if len(scopes) > 0 {
			policyFacts = append(policyFacts, Fact{Title: "Application Scopes", Value: join(scopes, ", ")})
		}

		card.Body = append(card.Body, FactSet{
			Type:  "FactSet",
			Facts: policyFacts,
		})
	}
}

func getString(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

func getFloat(data map[string]interface{}, key string) float64 {
	if data == nil {
		return 0
	}
	if val, ok := data[key].(float64); ok {
		return val
	}
	return 0
}

func getStringArray(data map[string]interface{}, key string) []string {
	if data == nil {
		return nil
	}
	if arr, ok := data[key].([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
