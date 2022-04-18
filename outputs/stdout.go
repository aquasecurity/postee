package outputs

import (
	"fmt"
	"os"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

type StdoutOutput struct {
	Name string
}

func (stdout StdoutOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:   stdout.Name,
		Enable: true,
		Type:   "stdout",
	}
}

func (stdout StdoutOutput) GetName() string { return stdout.Name }

func (stdout StdoutOutput) Init() error {
	return nil
}
func (stdout StdoutOutput) Send(data map[string]string) error {
	_, err := fmt.Fprintf(os.Stdout, "%s", data["description"])
	return err
}

func (stdout StdoutOutput) Terminate() error {
	return nil
}

func (stdout StdoutOutput) GetLayoutProvider() layout.LayoutProvider {
	return &formatting.HtmlProvider{}
}
