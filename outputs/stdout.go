package outputs

import (
	"fmt"
	"os"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

const (
	StdoutType = "stdout"
)

type StdoutOutput struct {
	Name string
}

func (stdout StdoutOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:   stdout.Name,
		Enable: true,
		Type:   StdoutType,
	}
}

func (stdout StdoutOutput) GetType() string {
	return StdoutType
}

func (stdout StdoutOutput) GetName() string { return stdout.Name }

func (stdout StdoutOutput) Init() error {
	return nil
}
func (stdout StdoutOutput) Send(data map[string]string) (string, error) {
	_, err := fmt.Fprintf(os.Stdout, "%s", data["description"])
	return EmptyID, err
}

func (stdout StdoutOutput) Terminate() error {
	return nil
}

func (stdout StdoutOutput) GetLayoutProvider() layout.LayoutProvider {
	return &formatting.HtmlProvider{}
}
