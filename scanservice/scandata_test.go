package scanservice

import (
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/settings"
	"sync"
	"testing"
)

var (
	plugin1 = "jira"
	plugin2 = "email"

	scan1 = map[string]string{"title": "title1", "description": "<p>description1</p>\n", "url": "url1"}
	scan2 = map[string]string{"title": "title2", "description": "<p>description2</p>\n", "url": "url2"}
	scan3 = map[string]string{"title": "title3", "description": "<p>description3</p>\n", "url": "url3"}
	scan4 = map[string]string{"title": "title4", "description": "<p>description4</p>\n", "url": "url4"}
)

type DemoPlugin struct {
	wg   sync.WaitGroup
	mu   sync.Mutex
	Sent bool
	name string
	lay  layout.LayoutProvider
	sets *settings.Settings
	t    *testing.T
}

func (plg *DemoPlugin) Init() error { return nil }
func (plg *DemoPlugin) Send(data map[string]string) error {
	plg.mu.Lock()
	plg.Sent = true
	plg.mu.Unlock()
	plg.t.Logf("Sending data via %q\n", plg.name)
	plg.wg.Done()
	return nil
}

func (plg *DemoPlugin) Terminate() error { return nil }
func (plg *DemoPlugin) GetLayoutProvider() layout.LayoutProvider {
	return plg.lay
}
func (plg *DemoPlugin) GetSettings() *settings.Settings {
	return plg.sets
}
