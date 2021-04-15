package eventservice

import (
	"encoding/json"
	systemPlugins "github.com/aquasecurity/postee/plugins"
	"log"
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
		plugin.GetLayoutProvider()
		cnt := buildMapContent(buildTitleAndDescription(plugin.GetLayoutProvider(), webhook))
		go func(content map[string]string, plgn systemPlugins.Plugin) {
			plgn.Send(content)
		}(cnt, plugin)
	}
}
