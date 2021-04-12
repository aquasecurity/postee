package uiserver

import (
	"log"
	"github.com/gorilla/mux"
	"net/http"
)

type uiServer struct {
	webPath string
	port string
	cfgPath string
	boltDbPath string
	updateUrl string
	updateKey string
	router *mux.Router
}

func Instance(web, port, cfg, boltDb, updateUrl, updateKey string) *uiServer {
	server := &uiServer{
		webPath: web,
		port: port,
		cfgPath: cfg,
		boltDbPath: boltDb,
		updateUrl: updateUrl,
		updateKey: updateKey,
		router: mux.NewRouter().StrictSlash(true),
	}
	server.router.HandleFunc("/plugins", server.pluginList).Methods("GET")
	server.router.HandleFunc("/plugins/{plugin}", server.pluginDetails).Methods("GET", "POST", "UPDATE", "DELETE")
	return server
}

func (srv *uiServer) Start()  {
	log.Print("UI Postee server starting...")
	http.ListenAndServe(":"+srv.port, srv.router)
}

func (srv *uiServer) Stop() {
	log.Print("UI Postee server stopped!")
}