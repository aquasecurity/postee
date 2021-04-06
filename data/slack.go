package data

type SlackTextBlock struct {
	TypeField string `json:"type"`
	TextField string `json:"text"`
}

type SlackBlock struct {
	TypeField string           `json:"type"`
	TextField *SlackTextBlock  `json:"text,omitempty"`
	Fields    []SlackTextBlock `json:"fields,omitempty"`
}
