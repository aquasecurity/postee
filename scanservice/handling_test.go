package scanservice

import (
	"testing"
)

func TestSchedulersStop(t *testing.T) {
	/*
	demoPlugins := make(map[string]plugins.Plugin)
	demoPlugins["pl0"] = nil
	hook := &plugins.WebhookPlugin{
		Url:             "",
		WebhookSettings: nil,
	}
	demoPlugins["pl1"] = hook

	hook2 := &plugins.WebhookPlugin{
		Url: "",
		WebhookSettings: &settings.Settings{
			IsScheduleRun: make(chan struct{}),
		},
	}
	demoPlugins["pl2"] = hook2
	schedulersStop(demoPlugins)
	if _, ok := <-hook2.GetSettings().IsScheduleRun; ok {
		t.Error("schedulersStop didn't stop the scheduler!")
	}

	 */
}
