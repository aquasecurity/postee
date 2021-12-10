package outputs

import (
	"bytes"
	"strings"

	"github.com/aquasecurity/postee/layout"
)

const posteeDocsUrl = "https://github.com/aquasecurity/postee#general-settings"

func buildShortMessage(server, urls string, provider layout.LayoutProvider) string {
	var builder bytes.Buffer
	if len(server) > 0 {
		builder.WriteString(provider.P("This message is too long to display here. Please visit the link to read the content."))
		links := strings.Split(urls, "\n")
		for _, link := range links {
			builder.WriteString(provider.P(provider.A(link, link)))
		}
	} else {
		builder.WriteString(provider.P("Please configure Aqua server url to see entire message."))
		builder.WriteString(provider.P(provider.A(posteeDocsUrl, posteeDocsUrl)))
	}
	return builder.String()
}
