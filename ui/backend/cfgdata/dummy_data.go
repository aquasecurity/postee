package cfgdata

type PluginSettings struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enable          bool     `json:"enable"`
	Url             string   `json:"url,omitempty"`
	User            string   `json:"user,omitempty"`
	Password        string   `json:"password,omitempty"`
	TlsVerify       bool     `json:"tls_verify,omitempty"`
	ProjectKey      string   `json:"project_key,omitempty" structs:"project_key,omitempty"`
	IssueType       string   `json:"issuetype,omitempty" structs:"issuetype"`
	BoardName       string   `json:"board,omitempty" structs:"board,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	Assignee        []string `json:"assignee,omitempty"`
	Description     string
	Summary         string            `json:"summary,omitempty"`
	FixVersions     []string          `json:"fixVersions,omitempty"`
	AffectsVersions []string          `json:"affectsVersions,omitempty"`
	Labels          []string          `json:"labels,omitempty"`
	Sprint          string            `json:"sprint,omitempty"`
	Unknowns        map[string]string `json:"unknowns" structs:"unknowns,omitempty"`

	Host       string   `json:"host"`
	Port       string   `json:"port"`
	Recipients []string `json:"recipients"`
	Sender     string   `json:"sender"`
	Token      string   `json:"token"`
	UseMX      bool     `json:"useMX"`

	PolicyMinVulnerability string   `json:"Policy-Min-Vulnerability"`
	PolicyRegistry         []string `json:"Policy-Registry"`
	PolicyImageName        []string `json:"Policy-Image-Name"`
	PolicyNonCompliant     bool     `json:"Policy-Non-Compliant"`
	PolicyShowAll          bool     `json:"Policy-Show-All"`

	IgnoreRegistry  []string `json:"Ignore-Registry"`
	IgnoreImageName []string `json:"Ignore-Image-Name"`

	AggregateIssuesNumber  int    `json:"Aggregate-Issues-Number"`
	AggregateIssuesTimeout string `json:"Aggregate-Issues-Timeout"`
	InstanceName           string `json:"instance"`
	PolicyOnlyFixAvailable bool   `json:"Policy-Only-Fix-Available"`

	PolicyOPA []string `json:"Policy-OPA"`

	AquaServer      string `json:"AquaServer"`
	DBMaxSize       int    `json:"Max_DB_Size"`
	DBRemoveOldData int    `json:"Delete_Old_Data"`
	DBTestInterval  int    `json:"DbVerifyInterval"`

	SizeLimit int `json:"SizeLimit"`
}

type Settings struct {
	PluginName             string
	PolicyMinVulnerability string
	PolicyRegistry         []string
	PolicyImageName        []string
	PolicyNonCompliant     bool
	IgnoreRegistry         []string
	IgnoreImageName        []string

	PolicyOPA []string

	AggregateIssuesNumber   int
	AggregateTimeoutSeconds int
	IsScheduleRun           bool
	PolicyOnlyFixAvailable  bool
	PolicyShowAll           bool
	AquaServer              string
}
