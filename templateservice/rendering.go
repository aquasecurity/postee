package templateservice

import (
	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/layout"
	"log"
)

func (t *Template) Render(input data.AquaInput, provider layout.LayoutProvider, server *string) map[string]string {
	scan := &data.ScanImageInfo{}
	prev := &data.ScanImageInfo{}
	if input["image"] != nil {
		log.Print("There is an image")
	}
	return getContent(scan, prev, provider, server)
}
