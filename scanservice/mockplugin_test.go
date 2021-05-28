package scanservice

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
)

type MockOutput struct {
	sender func(data map[string]string) error
}

func (plg *MockOutput) Init() error                              { return nil }
func (plg *MockOutput) Send(data map[string]string) error        { return nil }
func (plg *MockOutput) Terminate() error                         { return nil }
func (plg *MockOutput) GetLayoutProvider() layout.LayoutProvider { return new(formatting.HtmlProvider) }
