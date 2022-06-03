package uiserver

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func (srv *uiServer) getEvents(w http.ResponseWriter, r *http.Request) {
	log.Printf("configured config path %s", srv.cfgPath)

	posteeUrl := os.Getenv("POSTEE_UI_UPDATE_URL")
	if len(posteeUrl) <= 0 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No Postee URL configured, set POSTEE_UI_UPDATE_URL to the Postee URL"))
	}

	resp, err := http.Get(posteeUrl + "/events")
	if err != nil {
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte("Unable to reach Postee at URL: " + posteeUrl + "/events" + "err: " + err.Error()))
	}

	currentEvents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed to read events: " + err.Error()))
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(http.StatusOK)
	w.Write(currentEvents)
}
