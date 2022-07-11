package actions

import (
	"testing"

	"github.com/aquasecurity/postee/v2/layout"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/stretchr/testify/assert"
)

func Test_buildShortMessage(t *testing.T) {
	testCases := []struct {
		name        string
		provider    layout.LayoutProvider
		inputServer string
		inputUrls   string
		want        string
	}{
		{
			name:        "happy path with slack provider",
			provider:    new(formatting.SlackMrkdwnProvider),
			inputServer: "foo.com",
			inputUrls:   "foo1.com",
			want:        `{"type":"section","text":{"type":"mrkdwn","text":"This message is too long to display here. Please visit the link to read the content."}},{"type":"section","text":{"type":"mrkdwn","text":"\u003cfoo1.com|foo1.com\u003e"}},`,
		},
		{
			name:        "happy path with teams/html provider",
			inputServer: "foo.com",
			inputUrls:   "foo1.com",
			provider:    new(formatting.HtmlProvider),
			want: `<p>This message is too long to display here. Please visit the link to read the content.</p>
<p><a href='foo1.com'>foo1.com</a></p>
`,
		},
		{
			name:      "no configured aqua server",
			inputUrls: "foo1.com",
			provider:  new(formatting.HtmlProvider),
			want: `<p>Please configure Aqua server url to get link to entire scan results.</p>
<p><a href='https://aquasecurity.github.io/postee/settings/'>Postee settings</a></p>
`,
		},
		{
			name:        "no configured urls",
			inputServer: "foo.com",
			provider:    new(formatting.HtmlProvider),
			want: `<p>Unable to create link to entire scan results. Input message doesn't contain 'registry' and 'image' fields or they are empty</p>
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildShortMessage(tc.inputServer, tc.inputUrls, tc.provider)
			assert.Equal(t, tc.want, got, tc.name)
		})
	}
}
