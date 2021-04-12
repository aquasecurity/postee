package uiserver

import (
	"github.com/aquasecurity/postee/ui/backend/cfgdata"
	"net/http"
)

func (srv *uiServer) pluginList(w http.ResponseWriter, r *http.Request){
	d, err := cfgdata.ReadAll(srv.cfgPath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(d))
}
