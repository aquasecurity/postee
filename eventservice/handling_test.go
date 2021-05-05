package eventservice

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/plugins"
	"sync"
	"testing"
)

type demoEventPlugin struct {
	mut     sync.Mutex
	wasSend bool
	buff    *chan struct{}
}

func (plg *demoEventPlugin) resetSending() {
	plg.mut.Lock()
	defer plg.mut.Unlock()
	plg.wasSend = false
}
func (plg *demoEventPlugin) isSent() bool {
	plg.mut.Lock()
	defer plg.mut.Unlock()
	return plg.wasSend
}

func (plg *demoEventPlugin) Send(map[string]string) error {
	if plg.buff != nil {
		*plg.buff <- struct{}{}
	}
	plg.mut.Lock()
	plg.wasSend = true
	defer plg.mut.Unlock()
	return nil
}

func (plg *demoEventPlugin) Init() error      { return nil }
func (plg *demoEventPlugin) Terminate() error { return nil }
func (plg *demoEventPlugin) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}

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
		{"No json string", plgns, false},
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
