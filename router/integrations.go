package router

type ActionSettings struct {
	Name                  string                       `json:"name,omitempty"`
	Type                  string                       `json:"type,omitempty"`
	RunsOn                string                       `json:"runs-on,omitempty"`
	Enable                bool                         `json:"enable,omitempty"`
	Url                   string                       `json:"url,omitempty"`
	User                  string                       `json:"user,omitempty"`
	Password              string                       `json:"password,omitempty"`
	TlsVerify             bool                         `json:"tls-verify,omitempty"`
	ProjectKey            string                       `json:"project-key,omitempty" structs:"project-key,omitempty"`
	IssueType             string                       `json:"issuetype,omitempty" structs:"issuetype"`
	BoardName             string                       `json:"board,omitempty" structs:"board,omitempty"`
	Priority              string                       `json:"priority,omitempty"`
	Assignee              []string                     `json:"assignee,omitempty"`
	Summary               string                       `json:"summary,omitempty"`
	FixVersions           []string                     `json:"fix-versions,omitempty"`
	AffectsVersions       []string                     `json:"affects-versions,omitempty"`
	Labels                []string                     `json:"labels,omitempty"`
	Sprint                string                       `json:"sprint,omitempty"`
	Unknowns              map[string]string            `json:"unknowns,omitempty" structs:"unknowns,omitempty"`
	Host                  string                       `json:"host,omitempty"`
	Port                  int                          `json:"port,omitempty"`
	Recipients            []string                     `json:"recipients,omitempty"`
	Sender                string                       `json:"sender,omitempty"`
	Token                 string                       `json:"token,omitempty"`
	ClientHostName        string                       `json:"client-host-name,omitempty"`
	UseMX                 bool                         `json:"use-mx,omitempty"`
	InstanceName          string                       `json:"instance,omitempty"`
	SizeLimit             int                          `json:"size-limit,omitempty"`
	InputFile             string                       `json:"input-file,omitempty"`
	ExecScript            string                       `json:"exec-script,omitempty"`
	Env                   []string                     `json:"env,omitempty"`
	BodyFile              string                       `json:"body-file,omitempty"`
	BodyContent           string                       `json:"body-content,omitempty"`
	Method                string                       `json:"method,omitempty"`
	Timeout               string                       `json:"timeout,omitempty"`
	Headers               map[string][]string          `json:"headers,omitempty"`
	OrganizationId        string                       `json:"organization-id,omitempty"`
	KubeConfigFile        string                       `json:"kube-config-file,omitempty"`
	KubeLabelSelector     string                       `json:"kube-label-selector,omitempty"`
	KubeActions           map[string]map[string]string `json:"kube-actions,omitempty"`
	KubeNamespace         string                       `json:"kube-namespace,omitempty"`
	DockerImageName       string                       `json:"docker-image-name,omitempty"`
	DockerNetwork         string                       `json:"docker-network,omitempty"`
	DockerCmd             []string                     `json:"docker-cmd,omitempty"`
	DockerVolumes         map[string]string            `json:"docker-volume-mounts,omitempty"`
	DockerEnv             []string                     `json:"docker-env,omitempty"`
	Tags                  []string                     `json:"tags,omitempty"`
	Alias                 string                       `json:"alias,omitempty"`
	Entity                string                       `json:"entity,omitempty"`
	PagerdutyAuthToken    string                       `json:"pagerduty-auth-token,omitempty"`
	PagerdutyRoutingKey   string                       `json:"pagerduty-routing-key,omitempty"`
	DependencyTrackAPIKey string                       `json:"dependency-track-api-key,omitempty"`
}
