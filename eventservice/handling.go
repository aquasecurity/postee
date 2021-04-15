package eventservice

import (
	"encoding/json"
	systemPlugins "github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/regoservice"
	"log"
	"strings"
)

func (events *EventService) ResultHandling(input string, plugins map[string]systemPlugins.Plugin) {
	if plugins == nil {
		log.Print("ResultHandling error: plugins is null")
		return
	}
	webhook := &WebhookEvent{}
	if err := json.Unmarshal([]byte(input), webhook); err != nil {
		log.Printf("json.Unmarshal error for %q: %v", input, err)
		return
	}

	for _, plugin := range plugins {
		if settings := plugin.GetSettings(); settings != nil && len(settings.PolicyOPA) > 0 {
			log.Printf("Plugin %q uses OPA policies from '%s' for aufit action", settings.PluginName, strings.Join(settings.PolicyOPA, "','"))
			if res, err := regoservice.IsRegoCorrect(settings.PolicyOPA, input); err != nil {
				log.Printf("IsRegoCorrect error for audit action %q OPA policy: %v", settings.PluginName, err)
				continue
			} else if !res {
				log.Printf("Audit action %q doesn't match OPA/REGO rules for %q",
					input, settings.PluginName)
				continue
			}
		}

		cnt := buildMapContent(buildTitleAndDescription(plugin.GetLayoutProvider(), webhook))
		go func(content map[string]string, plgn systemPlugins.Plugin) {
			plgn.Send(content)
		}(cnt, plugin)
	}
}
