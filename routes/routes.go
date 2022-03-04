package routes

type InputRoute struct {
	Name             string   `json:"name"`
	Input            string   `json:"input"`
	InputFiles       []string `json:"input-files"`
	Outputs          []string `json:"outputs"`
	Plugins          Plugins  `json:"plugins"`
	Template         string   `json:"template"`
	SerializeOutputs bool     `json:"serialize-outputs"`
	Scheduling       chan struct{}
}

type Plugins struct {
	AggregateMessageNumber      int    `json:"aggregate-message-number"`
	AggregateMessageTimeout     string `json:"aggregate-message-timeout"`
	AggregateTimeoutSeconds     int
	UniqueMessageProps          []string `json:"unique-message-props"`
	UniqueMessageTimeout        string   `json:"unique-message-timeout"`
	UniqueMessageTimeoutSeconds int
}

func (route *InputRoute) IsSchedulerRun() bool {
	return route.Scheduling != nil
}
func (route *InputRoute) StartScheduler() {
	route.Scheduling = make(chan struct{})
}

func (route *InputRoute) StopScheduler() {
	if route.Scheduling != nil {
		close(route.Scheduling)
	}
}
