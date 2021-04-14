package uiserver

import (
	"encoding/json"
	"github.com/aquasecurity/postee/alertmgr"
	"io"
	"net/http"
)

func (srv *uiServer) updateConfig(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	inputJson, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Can't read JSON string", http.StatusBadRequest)
		return
	}
	plugins := &alertmgr.PluginSettings{}
	if err := json.Unmarshal(inputJson, plugins); err != nil {
		http.Error(w, "Can't read JSON string", http.StatusBadRequest)
		return
	}
}
