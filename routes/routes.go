package routes

type InputRoute struct {
	Name       string   `json:"name"`
	Input      string   `json:"input"`
	Outputs    []string `json:"outputs"`
	Plugins    Plugins  `json:"plugins"`
	Template   string   `json:"template"`
	scheduling chan struct{}
}

type Plugins struct {
	AggregateIssuesNumber   int    `json:"Aggregate-Issues-Number"`
	AggregateIssuesTimeout  string `json:"Aggregate-Issues-Timeout"`
	PolicyShowAll           bool   `json:"Policy-Show-All"`
	AggregateTimeoutSeconds int
}
