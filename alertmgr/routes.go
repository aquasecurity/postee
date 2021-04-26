package alertmgr

type InputRoutes struct {
	Name         string   `json:"name"`
	Integrations []string `json:"integrations"`
	PolicyOPA    []string `json:"Policy-OPA"`
}
