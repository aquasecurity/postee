package webserver

import (
	"net/http"
)

func (web *WebServer) reload(w http.ResponseWriter, r *http.Request) {
	if web.msgRouterProvider != nil {
		newRouter := web.msgRouterProvider(web.msgRouter)
		if newRouter != nil {
			web.msgRouter = newRouter
		}
	}
}
