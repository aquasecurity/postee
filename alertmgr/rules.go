package alertmgr

type InputRules struct {
	Name         string       `json:"name"`
	InputType    string       `json:"type"`
	Integrations []string     `json:"integrations"`
	Rules        []InputRules `json:"rules"`
}
