package scanservice

import (
	"testing"
)

func TestSchedulersStop(t *testing.T) {
	/*
		demoOutputs := make(map[string]outputs.Output)
		demoOutputs["pl0"] = nil
		hook := &outputs.WebhookOutput{
			Url:             "",
			WebhookSettings: nil,
		}
		demoOutputs["pl1"] = hook

		hook2 := &outputs.WebhookOutput{
			Url: "",
			WebhookSettings: &settings.Settings{
				IsScheduleRun: make(chan struct{}),
			},
		}
		demoOutputs["pl2"] = hook2
		schedulersStop(demoOutputs)
		if _, ok := <-hook2.GetSettings().IsScheduleRun; ok {
			t.Error("schedulersStop didn't stop the scheduler!")
		}

	*/
}
