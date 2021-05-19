package alertmgr

type Template struct {
	Name               string `json:"name"`
	Body               string `json:"body"`
	RegoPackage        string `json:"regopackage"`
	LegacyScanRenderer string `json:"legacyScanRenderer"`
	Url                string `json:"url"`
}
