package servicenow_api

const (
	BaseServer = "service-now.com/"
	baseApiUrl = "api/now/"
	tableApi   = "table/"
)

type ServiceNowData struct {
	ShortDescription string `json:"short_description"`
	WorkNotes        string `json:"work_notes"`
	Opened           string `json:"opened_at"`
	Caller           string `json:"caller_id"`
	Category         string `json:"category"`
	Subcategory      string `json:"subcategory"`
	Impact           int    `json:"impact"`
	Urgency          int    `json:"urgency"`
	State            int    `json:"state"`
	Description      string `json:"description"`
	AssignedTo       string `json:"assigned_to"`
	AssignmentGroup  string `json:"assignment_group"`
}
