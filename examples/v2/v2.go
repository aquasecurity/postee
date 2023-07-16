package main

import (
	"github.com/aquasecurity/postee/v2/log"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/routes"
)

var (
	msg = []byte(`{
	 	"foo":"3",
	 	"moo":"123",
	 	"image": "alpine"
	 }`)
)

func main() {
	// initialize new library instance
	rt, err := router.NewV2()
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Add a desired output integration
	err = rt.AddOutput(&data.OutputSettings{
		Name:   "stdout",
		Type:   "stdout",
		Enable: true,
	})
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Optional: Add more outputs
	err = rt.AddOutput(&data.OutputSettings{
		Name:   "my-teams",
		Type:   "teams",
		Url:    "", // Insert URL for teams webhook
		Enable: true,
	})
	if err != nil {
		log.Logger.Fatal(err)
	}

	// Configure the route
	// 1. Name (Mandatory)
	// 2. Which outputs to send notifications to
	// 3. The template that will be sent for each output
	rt.AddRoute(&routes.InputRoute{
		Name:     "test",
		Outputs:  []string{"stdout", "my-teams"},
		Template: "raw-message-json",
	})

	rt.SendNotifications(msg)
}
