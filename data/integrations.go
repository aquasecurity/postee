package data

type OutputSettings struct {
	Name            string              `json:"name,omitempty"`
	Type            string              `json:"type,omitempty"`
	Enable          bool                `json:"enable,omitempty"`
	Url             string              `json:"url,omitempty"`
	User            string              `json:"user,omitempty"`
	Password        string              `json:"password,omitempty"`
	TlsVerify       bool                `json:"tls-verify,omitempty"`
	ProjectKey      string              `json:"project-key,omitempty" structs:"project-key,omitempty"`
	IssueType       string              `json:"issuetype" structs:"issuetype"`
	BoardName       string              `json:"board,omitempty" structs:"board,omitempty"`
	Priority        string              `json:"priority,omitempty"`
	Assignee        []string            `json:"assignee,omitempty"`
	Summary         string              `json:"summary,omitempty"`
	FixVersions     []string            `json:"fix-versions,omitempty"`
	AffectsVersions []string            `json:"affects-versions,omitempty"`
	Labels          []string            `json:"labels,omitempty"`
	Sprint          string              `json:"sprint,omitempty"`
	Unknowns        map[string]string   `json:"unknowns" structs:"unknowns,omitempty"`
	Host            string              `json:"host,omitempty"`
	Port            int                 `json:"port,omitempty"`
	Recipients      []string            `json:"recipients,omitempty"`
	Sender          string              `json:"sender,omitempty"`
	Token           string              `json:"token,omitempty"`
	ClientHostName  string              `json:"client-host-name,omitempty"`
	UseMX           bool                `json:"use-mx,omitempty"`
	InstanceName    string              `json:"instance,omitempty"`
	SizeLimit       int                 `json:"size-limit,omitempty"`
	InputFile       string              `json:"input-file,omitempty"`
	Env             []string            `json:"env,omitempty"`
	BodyFile        string              `json:"bodyfile,omitempty"`
	Method          string              `json:"method,omitempty"`
	Timeout         string              `json:"timeout,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	Template        string              `json:"template,omitempty"`
	Language        string              `json:"language,omitempty"`
	UseAwsSes       bool                `json:"use-aws-ses,omitempty"`
	AwsSesConfig    map[string]string   `json:"aws-ses-config,omitempty"`
}

type OutputResponse struct {
	Type string
	Name string
	Key  string
	Url  string
}
