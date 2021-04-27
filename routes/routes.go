package routes

type InputRoutes struct {
	Name                    string `json:"name"`
	Input                   string `json:"input"`
	Output                  string `json:"output"`
	Template                string `json:"template"`
	AggregateIssuesNumber   int    `json:"Aggregate-Issues-Number"`
	AggregateIssuesTimeout  string `json:"Aggregate-Issues-Timeout"`
	PolicyShowAll           bool   `json:"Policy-Show-All"`
	AggregateTimeoutSeconds int
	scheduling              chan struct{}
}
