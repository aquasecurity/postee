package router

type Template struct {
	Name               string `json:"name,omitempty"`
	Body               string `json:"body,omitempty"`
	RegoPackage        string `json:"rego-package,omitempty"`
	LegacyScanRenderer string `json:"legacy-scan-renderer,omitempty"`
	Url                string `json:"url,omitempty"`
}
