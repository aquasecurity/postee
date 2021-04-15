package eventservice

import (
	"fmt"
	"github.com/aquasecurity/postee/layout"
)

func buildTitleAndDescription(provider layout.LayoutProvider, data *WebhookEvent) (title string, description string) {
	title = fmt.Sprintf("%s event", data.Type)
	d := GetMessage(data)
	description = provider.P(d)
	return
}

func buildMapContent(title, description string) map[string]string {
	content := make(map[string]string)
	content["title"] = title
	content["description"] = description
	return content
}
