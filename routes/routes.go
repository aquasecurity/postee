package routes

type InputRoute struct {
	Name       string   `json:"name"`
	Input      string   `json:"input"`
	Outputs    []string `json:"outputs"`
	Plugins    Plugins  `json:"plugins"`
	Template   string   `json:"template"`
	Scheduling chan struct{}
}

type Plugins struct {
	AggregateIssuesNumber   int    `json:"Aggregate-Issues-Number"`
	AggregateIssuesTimeout  string `json:"Aggregate-Issues-Timeout"`
	PolicyShowAll           bool   `json:"Policy-Show-All"`
	AggregateTimeoutSeconds int
}

func (route *InputRoute) IsSchedulerRun() bool {
	return route.Scheduling != nil
}
func (route *InputRoute) StartScheduler() {
	route.Scheduling = make(chan struct{})
}

func (route *InputRoute) StopScheduler() { //TODO scheduler should be stopped somewhere
	if route.Scheduling != nil {
		close(route.Scheduling)
	}
}
