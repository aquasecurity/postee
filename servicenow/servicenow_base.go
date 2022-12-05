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

type ServiceNowResponse struct {
	ServiceNowResult `json:"result"`
}

// ServiceNowResult list of response values: https://docs.servicenow.com/bundle/tokyo-application-development/page/integrate/inbound-rest/concept/c_TableAPI.html#table-POST
type ServiceNowResult struct {
	Parent                 string `json:"parent"`
	MadeSLA                string `json:"made_sla"`
	CausedBy               string `json:"caused_by"`
	WatchList              string `json:"watch_list"`
	UponReject             string `json:"upon_reject"`
	SysUpdatedOn           string `json:"sys_updated_on"`
	ChildIncidents         string `json:"child_incidents"`
	HoldReason             string `json:"hold_reason"`
	OriginTable            string `json:"origin_table"`
	TaskEffectiveNumber    string `json:"task_effective_number"`
	ApprovalHistory        string `json:"approval_history"`
	Number                 string `json:"number"`
	ResolvedBy             string `json:"resolved_by"`
	SysUpdatedBy           string `json:"sys_updated_by"`
	ServiceNowOpenedBy     `json:"opened_by"`
	UserInput              string `json:"user_input"`
	SysCreatedOn           string `json:"sys_created_on"`
	ServiceNowSysDomain    `json:"sys_domain"`
	State                  string             `json:"state"`
	RouteReason            string             `json:"route_reason"`
	SysCreatedBy           string             `json:"sys_created_by"`
	Knowledge              string             `json:"knowledge"`
	Order                  string             `json:"order"`
	CalendarStc            string             `json:"calendar_stc"`
	ClosedAt               string             `json:"closed_at"`
	CmdbCi                 string             `json:"cmdb_ci"`
	DeliveryPlan           string             `json:"delivery_plan"`
	Contract               string             `json:"contract"`
	Impact                 string             `json:"impact"`
	Active                 string             `json:"active"`
	WorkNotesList          string             `json:"work_notes_list"`
	BusinessService        string             `json:"business_service"`
	BusinessImpact         string             `json:"business_impact"`
	Priority               string             `json:"priority"`
	SysDomainPath          string             `json:"sys_domain_path"`
	Rfc                    string             `json:"rfc"`
	TimeWorked             string             `json:"time_worked"`
	ExpectedStart          string             `json:"expected_start"`
	OpenedAt               string             `json:"opened_at"`
	BusinessDuration       string             `json:"business_duration"`
	GroupList              string             `json:"group_list"`
	WorkEnd                string             `json:"work_end"`
	CallerID               ServiceNowCallerTo `json:"caller_id"`
	ReopenedTime           string             `json:"reopened_time"`
	ResolvedAt             string             `json:"resolved_at"`
	ApprovalSet            string             `json:"approval_set"`
	Subcategory            string             `json:"subcategory"`
	WorkNotes              string             `json:"work_notes"`
	UniversalRequest       string             `json:"universal_request"`
	ShortDescription       string             `json:"short_description"`
	CloseCode              string             `json:"close_code"`
	CorrelationDisplay     string             `json:"correlation_display"`
	DeliveryTask           string             `json:"delivery_task"`
	WorkStart              string             `json:"work_start"`
	AssignmentGroup        interface{}        `json:"assignment_group"`
	AdditionalAssigneeList string             `json:"additional_assignee_list"`
	BusinessStc            string             `json:"business_stc"`
	Cause                  string             `json:"cause"`
	Description            string             `json:"description"`
	OriginID               string             `json:"origin_id"`
	CalendarDuration       string             `json:"calendar_duration"`
	CloseNotes             string             `json:"close_notes"`
	Notify                 string             `json:"notify"`
	ServiceOffering        string             `json:"service_offering"`
	SysClassName           string             `json:"sys_class_name"`
	ClosedBy               string             `json:"closed_by"`
	FollowUp               string             `json:"follow_up"`
	ParentIncident         string             `json:"parent_incident"`
	SysID                  string             `json:"sys_id"`
	ContactType            string             `json:"contact_type"`
	ReopenedBy             string             `json:"reopened_by"`
	IncidentState          string             `json:"incident_state"`
	Urgency                string             `json:"urgency"`
	ProblemID              string             `json:"problem_id"`
	Company                string             `json:"company"`
	ReassignmentCount      string             `json:"reassignment_count"`
	ActivityDue            string             `json:"activity_due"`
	AssignedTo             interface{}        `json:"assigned_to"`
	Severity               string             `json:"severity"`
	Comments               string             `json:"comments"`
	Approval               string             `json:"approval"`
	SLADue                 string             `json:"sla_due"`
	CommentsAndWorkNotes   string             `json:"comments_and_work_notes"`
	DueDate                string             `json:"due_date"`
	SysModCount            string             `json:"sys_mod_count"`
	ReopenCount            string             `json:"reopen_count"`
	SysTags                string             `json:"sys_tags"`
	Escalation             string             `json:"escalation"`
	UponApproval           string             `json:"upon_approval"`
	CorrelationID          string             `json:"correlation_id"`
	Location               string             `json:"location"`
	Category               string             `json:"category"`
}

type ServiceNowOpenedBy struct {
	Link  string `json:"link"`
	Value string `json:"value"`
}

type ServiceNowSysDomain struct {
	Link  string `json:"link"`
	Value string `json:"value"`
}

type ServiceNowCallerTo struct {
	Link  string `json:"link"`
	Value string `json:"value"`
}
