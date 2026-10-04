package msgservice

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/postee/v2/routes"
)

func TestEnrichMsgTemplateOptions(t *testing.T) {
	opts := routes.TemplateOptions{Fields: []string{"vulnerability_summary"}, TitleFormat: "summary"}
	route := &routes.InputRoute{
		Name: "policy-1",
		OverrideTemplateOptions: map[string]routes.TemplateOptions{
			"email-1": opts,
			"teams-1": {},
		},
	}
	in := map[string]interface{}{"image": "img:1.0"}
	svc := &MsgService{}

	t.Run("adds the options of the named output", func(t *testing.T) {
		richIn := svc.enrichMsg(in, route, "email-1", "")
		assert.Equal(t, opts, richIn[TemplateOptionsAttribute])
	})

	t.Run("no key for an output without options", func(t *testing.T) {
		assert.NotContains(t, svc.enrichMsg(in, route, "webhook-1", ""), TemplateOptionsAttribute)
	})

	t.Run("no key for empty options", func(t *testing.T) {
		assert.NotContains(t, svc.enrichMsg(in, route, "teams-1", ""), TemplateOptionsAttribute)
	})

	t.Run("no key for a route without options", func(t *testing.T) {
		assert.NotContains(t, svc.enrichMsg(in, &routes.InputRoute{Name: "policy-2"}, "email-1", ""), TemplateOptionsAttribute)
	})

	t.Run("shared input is not changed", func(t *testing.T) {
		svc.enrichMsg(in, route, "email-1", "")
		assert.NotContains(t, in, TemplateOptionsAttribute)
	})
}
