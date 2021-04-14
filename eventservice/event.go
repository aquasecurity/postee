package eventservice

import "log"

type EventService struct {
}

func (events *EventService) EventHandling(hook string) {
	log.Print("[EventService]", hook)
}
