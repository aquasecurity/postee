package eventservice

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/settings"
	"testing"
)

type demoEventPlugin struct {
	wasSend bool
	buff    *chan struct{}
}

func (plg *demoEventPlugin) Send(map[string]string) error {
	if plg.buff != nil {
		*plg.buff <- struct{}{}
	}
	return nil
}

func (plg *demoEventPlugin) Init() error      { return nil }
func (plg *demoEventPlugin) Terminate() error { return nil }
func (plg *demoEventPlugin) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}
func (plg *demoEventPlugin) GetSettings() *settings.Settings { return nil }

func TestHandlingResult(t *testing.T) {
	ch := make(chan struct{})
	demoPlugin := &demoEventPlugin{}
	demoPlugin.buff = &ch

	plgns := make(map[string]plugins.Plugin)
	plgns["demoEventPlugin"] = demoPlugin

	tests := []struct {
		input   string
		plugins map[string]plugins.Plugin
		wasSent bool
	}{
		{"nostring", nil, false},
		{"No json sting", plgns, false},
		{correctLoginJson, plgns, true},
	}

	events := &EventService{}
	for _, test := range tests {
		demoPlugin.wasSend = false
		events.ResultHandling(test.input, test.plugins)
		if test.wasSent {
			<-ch
		}
	}
}
