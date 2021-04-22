package uiserver

import (
	"fmt"
	"io"
	"net/http"
)

func (srv *uiServer) testPluginConfig(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	u := fmt.Sprintf("%s/test?key=%s", srv.updateUrl, srv.updateKey) //TODO rename properties

	resp, err := http.Post(u, "application/json", r.Body)

	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)

}
