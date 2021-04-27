package templateservice

import (
	"encoding/json"
	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/layout"
)

func (t *Template) Render(source []byte, input data.AquaInput, provider layout.LayoutProvider, server *string) (map[string]string, error) {
	scan := &data.ScanImageInfo{}
	prev := &data.ScanImageInfo{}
	if input["image"] != nil {
		err := json.Unmarshal(source, scan)
		if err != nil {
			return nil, err
		}
	}
	return getContent(scan, prev, provider, server), nil
}
