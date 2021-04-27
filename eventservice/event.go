package eventservice

type EventService struct{}

type WebhookEvent struct {
	Action    string `json:"action,omitempty"`
	Adjective string `json:"adjective,omitempty"`
	Category  string `json:"category,omitempty"`
	Date      uint64 `json:"date,omitempty"`
	Id        int    `json:"id,omitempty"`
	Result    int    `json:"result,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	Time      uint64 `json:"time,omitempty"`
	Type      string `json:"type,omitempty"`
	User      string `json:"user,omitempty"`
	Version   string `json:"version,omitempty"`
}
