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
		w.WriteHeader(http.StatusBadRequest)
		log.Println("No Postee URL configured, set POSTEE_UI_UPDATE_URL to the Postee URL")
		return
	}

	resp, err := http.Get(posteeUrl + "/events")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Unable to reach Postee at URL: " + posteeUrl + "/events" + " err: " + err.Error())
		return
	}

	currentEvents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Failed to read events: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(currentEvents)
}
