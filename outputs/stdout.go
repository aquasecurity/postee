package outputs

import (
	"fmt"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"os"
)

type StdoutOutput struct {
	Name string
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
