package scanservice

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/settings"
)

type MockPlugin struct {
	sender func(data map[string]string) error
	sets   *settings.Settings
}

func (plg *MockPlugin) Init() error                              { return nil }
func (plg *MockPlugin) Send(data map[string]string) error        { return nil }
func (plg *MockPlugin) Terminate() error                         { return nil }
func (plg *MockPlugin) GetLayoutProvider() layout.LayoutProvider { return new(formatting.HtmlProvider) }
func (plg *MockPlugin) GetSettings() *settings.Settings          { return plg.sets }
