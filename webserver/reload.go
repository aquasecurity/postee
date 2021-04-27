package webserver

import (
	"net/http"

	"github.com/aquasecurity/postee/alertmgr"
)

func (web *WebServer) reload(w http.ResponseWriter, r *http.Request) {
	alertmgr.Instance().ReloadConfig()
}
