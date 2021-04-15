package uiserver

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type uiServer struct {
	port       string
	cfgPath    string
	boltDbPath string
	updateUrl  string
	updateKey  string
	router     *mux.Router
}

func Instance(webLocalPath, port, cfg, updateUrl, updateKey string) *uiServer {
	server := &uiServer{
		port:      port,
		cfgPath:   cfg,
		updateUrl: updateUrl,
		updateKey: updateKey,
		router:    mux.NewRouter().StrictSlash(true),
	}
	server.router.HandleFunc("/update", server.updateConfig).Methods("POST")
	server.router.HandleFunc("/plugins", server.pluginList).Methods("GET")
	server.router.HandleFunc("/plugins/stats", server.plgnStats).Methods("GET")

	web := &localWebServer{
		localPath: webLocalPath,
		url:       "/",
	}
	server.router.PathPrefix("/").Handler(web)
	return server
}

func (srv *uiServer) Start() {
	log.Print("UI Postee server starting...")
	http.ListenAndServe(":"+srv.port, srv.router)
}

func (srv *uiServer) Stop() {
	log.Print("UI Postee server stopped!")
}
