package webserver

import (
	"github.com/aquasecurity/postee/alertmgr"
	"github.com/aquasecurity/postee/utils"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
)

func (ctx *WebServer) tenantHandler(w http.ResponseWriter, r *http.Request) {
	route,ok := mux.Vars(r)["route"]
	if !ok || len(route) == 0 {
		log.Printf("Failed route: %q", route)
		ctx.writeResponse(w, http.StatusBadRequest, "failed route")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed ioutil.ReadAll: %s", err)
		ctx.writeResponseError(w, http.StatusInternalServerError, err)
		return
	}

	defer r.Body.Close()
	utils.Debug("%s\n\n", string(body))
	alertmgr.Instance().SendByRoute(route, body)
	ctx.writeResponse(w, http.StatusOK, "")
}
