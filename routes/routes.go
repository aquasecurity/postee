package routes

type InputRoute struct {
	Name             string        `json:"name,omitempty"`
	Input            string        `json:"input,omitempty"`
	InputFiles       []string      `json:"input-files,omitempty"`
	Actions          []string      `json:"actions,omitempty"`
	Plugins          Plugins       `json:"plugins,omitempty"`
	Template         string        `json:"template,omitempty"`
	SerializeActions bool          `json:"serialize-actions,omitempty"`
	Scheduling       chan struct{} `json:"-"`
}

type Plugins struct {
	AggregateMessageNumber      int      `json:"aggregate-message-number,omitempty"`
	AggregateMessageTimeout     string   `json:"aggregate-message-timeout,omitempty"`
	AggregateTimeoutSeconds     int      `json:"aggregate-timeout-seconds,omitempty"`
	UniqueMessageProps          []string `json:"unique-message-props,omitempty"`
	UniqueMessageTimeout        string   `json:"unique-message-timeout,omitempty"`
	UniqueMessageTimeoutSeconds int      `json:"unique-message-timeout-seconds,omitempty"`
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
