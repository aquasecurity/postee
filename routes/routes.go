package routes

type InputRoute struct {
	Name             string            `json:"name"`
	Input            string            `json:"input"`
	InputFiles       []string          `json:"input-files"` // should be empty in library mode
	Outputs          []string          `json:"outputs"`
	Plugins          Plugins           `json:"plugins"`
	Template         string            `json:"template"`
	OverrideTemplate map[string]string `json:"overrideTemplates"` // a map between a output and a template
	// OverrideTemplateOptions maps an output to options for its Custom Fields Message template (field list, title format)
	OverrideTemplateOptions map[string]TemplateOptions `json:"overrideTemplateOptions,omitempty"`
	Scheduling              chan struct{}              `json:"-"`
}

// TemplateOptions are per-output options that the Custom Fields Message templates read from input.template_options.
type TemplateOptions struct {
	Fields      []string `json:"fields,omitempty"`
	TitleFormat string   `json:"title_format,omitempty"`
}

func (o TemplateOptions) IsEmpty() bool {
	return len(o.Fields) == 0 && o.TitleFormat == ""
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
