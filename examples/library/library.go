package main

import (
	"fmt"

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

	// Used for duplications persistent storage
	duplications = make(map[string]struct{})
)

func main() {
	// initialize new library instance
	router.New()

	// Add optional output
	err := router.AddOutput(&data.OutputSettings{
		Name:   "stdout",
		Type:   "stdout",
		Enable: true,
	})
	if err != nil {
		log.Logger.Fatal(err)
	}

	err = router.AddOutput(&data.OutputSettings{
		Name:   "stdout2",
		Type:   "stdout",
		Enable: true,
	})
	if err != nil {
		log.Logger.Fatal(err)
	}

	// No need to add templates - already embedded
	log.Logger.Infof("Embedded Templates: %v", router.ListTemplates())

	router.AddRoute(&routes.InputRoute{
		Name:     "test",
		Outputs:  []string{"stdout", "stdout2"},
		Template: "raw-message-json",
		Input:    `contains(input.image, "alpine")`,
		Plugins: routes.Plugins{
			UniqueMessageProps: []string{"image"},
		},
	})

	routes := router.Evaluate(msg)

	for _, name := range routes {
		key, err := router.GetMessageUniqueId(msg, name)
		if err != nil {
			log.Logger.Fatal(err)
		}

		// key should contains the route name for uniqueness
		origKey := fmt.Sprintf("%s-%s", name, key)
		checkAndSend(origKey, name, msg)

		//second send for same key - should be blocked
		checkAndSend(origKey, name, msg)
	}

}

func checkAndSend(key, name string, msg []byte) {
	if !checkDedupe(key) {
		send(key, name, msg)
		return
	}
	log.Logger.Infof("a message with key '%s' already has been sent for route: %s\n", key, name)
}

func send(key, routeName string, msg []byte) {
	router.SendByRoute(msg, routeName)
	if key != "" {
		duplications[key] = struct{}{}
	}
}

func checkDedupe(key string) bool {
	if key == "" {
		return false
	}
	_, ok := duplications[key]
	return ok
}
