package outputs

import "github.com/aquasecurity/postee/v2/layout"

type OpsGenieOutput struct {
}

func (ops *OpsGenieOutput) GetName() string {
	return ""
}

func (ops *OpsGenieOutput) Init() error {
	return nil
}

func (ops *OpsGenieOutput) Send(map[string]string) error {
	return nil
}

func (ops *OpsGenieOutput) Terminate() error {
	return nil
}

func (ops *OpsGenieOutput) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
