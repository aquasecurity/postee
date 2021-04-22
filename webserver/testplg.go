package webserver

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/aquasecurity/postee/alertmgr"
	"github.com/aquasecurity/postee/layout"
)

func (web *WebServer) testSettings(w http.ResponseWriter, r *http.Request) {
	plgSettings := &alertmgr.PluginSettings{}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Can't read JSON string", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, plgSettings); err != nil {
		http.Error(w, "Can't read JSON string", http.StatusBadRequest)
		return
	}

	plg := alertmgr.BuildAndInitPlg(plgSettings)

	testPayload := make(map[string]string)

	testPayload["title"] = "Postee test title"
	testPayload["description"] = layout.GenTestDescription(plg.GetLayoutProvider(), "Postee test description")

	log.Printf("description is: %s \n", testPayload["description"])

	err = plg.Send(testPayload)

	if err != nil {
		//TODO provide method to write error response as JSON
		http.Error(w, fmt.Sprintf("Can't test integration: %s \n", err), http.StatusBadRequest)
		return
	}

}
