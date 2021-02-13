package servicenow_api

const (
	BaseServer = "service-now.com/"
	baseApiUrl = "api/now/"
	tableApi   = "table/"
)

type ServiceNowData struct {
	ShortDescription string `json:"short_description"`
	WorkNotes        string `json:"work_notes"`
}
