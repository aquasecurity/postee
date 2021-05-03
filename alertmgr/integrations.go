package alertmgr

type PluginSettings struct {
	Name            string            `json:"name,omitempty"`
	Type            string            `json:"type,omitempty"`
	Enable          bool              `json:"enable,omitempty"`
	Url             string            `json:"url,omitempty"`
	User            string            `json:"user,omitempty"`
	Password        string            `json:"password,omitempty"`
	TlsVerify       bool              `json:"tls_verify,omitempty"`
	ProjectKey      string            `json:"project_key,omitempty" structs:"project_key,omitempty"`
	IssueType       string            `json:"issuetype" structs:"issuetype"`
	BoardName       string            `json:"board,omitempty" structs:"board,omitempty"`
	Priority        string            `json:"priority,omitempty"`
	Assignee        []string          `json:"assignee,omitempty"`
	Summary         string            `json:"summary,omitempty"`
	FixVersions     []string          `json:"fixVersions,omitempty"`
	AffectsVersions []string          `json:"affectsVersions,omitempty"`
	Labels          []string          `json:"labels,omitempty"`
	Sprint          string            `json:"sprint,omitempty"`
	Unknowns        map[string]string `json:"unknowns" structs:"unknowns,omitempty"`
	Host            string            `json:"host,omitempty"`
	Port            string            `json:"port,omitempty"`
	Recipients      []string          `json:"recipients,omitempty"`
	Sender          string            `json:"sender,omitempty"`
	Token           string            `json:"token,omitempty"`
	UseMX           bool              `json:"useMX,omitempty"`
	InstanceName    string            `json:"instance,omitempty"`
	SizeLimit       int               `json:"SizeLimit,omitempty"`
}
