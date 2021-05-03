package scanservice

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
)

type MockPlugin struct {
	sender func(data map[string]string) error
}

func (plg *MockPlugin) Init() error                              { return nil }
func (plg *MockPlugin) Send(data map[string]string) error        { return nil }
func (plg *MockPlugin) Terminate() error                         { return nil }
func (plg *MockPlugin) GetLayoutProvider() layout.LayoutProvider { return new(formatting.HtmlProvider) }
