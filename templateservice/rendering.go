package templateservice

import (
	"encoding/json"
	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/regoservice"
)

func (t *Template) Render(source []byte, input data.AquaInput, provider layout.LayoutProvider, rules *string, server *string) (map[string]string, error) {
	scan := &data.ScanImageInfo{}
	prev := &data.ScanImageInfo{}
	if input["image"] != nil {
		err := json.Unmarshal(source, scan)
		if err != nil {
			return nil, err
		}
	}

	regoservice.BuildRegoTemplate(input, rules)

	return getContent(scan, prev, provider, server), nil
}
