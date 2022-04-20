package actions

import (
	"bytes"
	"log"
	"net/url"
	"strings"

	"github.com/aquasecurity/postee/v2/layout"
)

const posteeDocsUrl = "https://github.com/aquasecurity/postee#settings"

func buildShortMessage(server, urls string, provider layout.LayoutProvider) string {
	var builder bytes.Buffer
	if len(server) > 0 && len(urls) > 0 {
		builder.WriteString(provider.P("This message is too long to display here. Please visit the link to read the content."))
		links := strings.Split(urls, "\n")
		for _, link := range links {
			linkTitle, err := url.QueryUnescape(link)
			if err != nil {
				log.Printf("Query unescape error: %s", err)
			}
			builder.WriteString(provider.P(provider.A(link, linkTitle)))
		}
	} else if len(server) == 0 {
		builder.WriteString(provider.P("Please configure Aqua server url to get link to entire scan results."))
		builder.WriteString(provider.P(provider.A(posteeDocsUrl, "Postee settings")))
	} else {
		builder.WriteString(provider.P("Unable to create link to entire scan results. Input message doesn't contain 'registry' and 'image' fields or they are empty"))
	}
	return builder.String()
}
