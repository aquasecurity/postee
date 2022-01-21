package webserver

import (
	"net/http"

	"github.com/aquasecurity/postee/v2/router"
)

func (web *WebServer) reload(w http.ResponseWriter, r *http.Request) {
	router.Instance().ReloadConfig()
}
