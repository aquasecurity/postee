package eventservice

import (
	"github.com/aquasecurity/postee/plugins"
	"log"
)

type EventService struct {
}

func (events *EventService) ResultHandling(input string, plugins map[string]plugins.Plugin) {
	log.Print("[EventService]", input)
}
