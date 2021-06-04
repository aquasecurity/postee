package scanservice

import (
	"sync"
	"testing"

	"github.com/aquasecurity/postee/layout"
)

var (
	output1 = "jira"
	output2 = "email"

	scan1 = map[string]string{"title": "title1", "description": "<p>description1</p>\n", "url": "url1"}
	scan2 = map[string]string{"title": "title2", "description": "<p>description2</p>\n", "url": "url2"}
	scan3 = map[string]string{"title": "title3", "description": "<p>description3</p>\n", "url": "url3"}
	scan4 = map[string]string{"title": "title4", "description": "<p>description4</p>\n", "url": "url4"}

	scanWithOwners1 = map[string]string{"title": "title1", "description": "<p>description1</p>\n", "url": "url1", "owners":"owner1@mail.com"}
	scanWithOwners2 = map[string]string{"title": "title2", "description": "<p>description2</p>\n", "url": "url2", "owners":"owner2@mail.com"}
)

type DemoOutput struct {
	wg   sync.WaitGroup
	mu   sync.Mutex
	Sent bool
	name string
	lay  layout.LayoutProvider
	t    *testing.T
}

func (plg *DemoOutput) Init() error { return nil }
func (plg *DemoOutput) Send(data map[string]string) error {
	plg.mu.Lock()
	plg.Sent = true
	plg.mu.Unlock()
	plg.t.Logf("Sending data via %q\n", plg.name)
	plg.wg.Done()
	return nil
}

func (plg *DemoOutput) Terminate() error { return nil }
func (plg *DemoOutput) GetLayoutProvider() layout.LayoutProvider {
	return plg.lay
}
