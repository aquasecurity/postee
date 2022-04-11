package outputs

import (
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"log"
)

type OpsGenieOutput struct {
	Name string
}

func (ops *OpsGenieOutput) GetName() string {
	return ops.Name
}

func (ops *OpsGenieOutput) Init() error {
	log.Printf("Starting OpsGenie output %q....", ops.Name)
	return nil
}

func (ops *OpsGenieOutput) Send(input map[string]string) error {
	log.Printf("Sending to %q was successful!", ops.Name)
	return nil
}

func (*OpsGenieOutput) Terminate() error {
	return nil
}

func (ops *OpsGenieOutput) GetLayoutProvider() layout.LayoutProvider {
	/*TODO come up with smaller interface that doesn't include GetLayoutProvider()*/
	return new(formatting.SlackMrkdwnProvider)
}
