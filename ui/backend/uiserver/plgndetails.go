package uiserver

import (
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func (srv *uiServer) pluginDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Printf("Request %q", vars["plugin"])

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(vars["plugin"]))
}
