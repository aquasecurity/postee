package webserver

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/aquasecurity/postee/alertmgr"
	"github.com/aquasecurity/postee/utils"
	"github.com/gorilla/mux"
)

type WebServer struct {
	quit   chan struct{}
	router *mux.Router
}

var initCtx sync.Once
var wsCtx *WebServer

func Instance() *WebServer {
	initCtx.Do(func() {
		wsCtx = &WebServer{
			quit:   make(chan struct{}),
			router: mux.NewRouter().StrictSlash(true),
		}
	})
	return wsCtx
}
func (ctx *WebServer) withApiKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		correctKey := os.Getenv("RELOAD_KEY")

		if len(correctKey) == 0 {
			log.Print("reload API key is empty! You need to set an environment variable 'RELOAD_KEY'")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if key := r.URL.Query().Get("key"); key != correctKey {
			log.Printf("reload API received an incorrect key %q", key)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (ctx *WebServer) Start(host, tlshost string) {
	log.Printf("Starting WebServer....")

	rootDir, _ := utils.GetRootDir()
	certPem := filepath.Join(rootDir, "cert.pem")
	keyPem := filepath.Join(rootDir, "key.pem")

	if ok := utils.PathExists(keyPem); ok != true {
		utils.GenerateCertificate(keyPem, certPem)
	}

	if os.Getenv("AQUAALERT_CERT_PEM") != "" {
		certPem = os.Getenv("AQUAALERT_CERT_PEM")
	}

	if os.Getenv("AQUAALERT_KEY_PEM") != "" {
		keyPem = os.Getenv("AQUAALERT_KEY_PEM")
	}

	ctx.router.HandleFunc("/", ctx.sessionHandler(ctx.scanHandler)).Methods("POST")
	ctx.router.HandleFunc("/scan", ctx.sessionHandler(ctx.scanHandler)).Methods("POST")
	ctx.router.HandleFunc("/ping", ctx.sessionHandler(ctx.pingHandler)).Methods("POST")

	ctx.router.HandleFunc("/test", ctx.withApiKey(ctx.testSettings)).Methods("POST")
	ctx.router.HandleFunc("/reload", ctx.withApiKey(ctx.reload)).Methods("GET")

	go func() {
		log.Printf("Listening for HTTP on %s ", host)
		log.Fatal(http.ListenAndServe(host, ctx.router))
	}()
	go func() {
		log.Printf("Listening for HTTPS on %s", tlshost)
		log.Fatal(http.ListenAndServeTLS(tlshost, certPem, keyPem, ctx.router))
	}()
}

func (ctx *WebServer) Terminate() {
	log.Printf("Terminating WebServer....")
	close(ctx.quit)
}

func (ctx *WebServer) sessionHandler(f func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
	}
}

func (ctx *WebServer) scanHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed ioutil.ReadAll: %s\n", err)
		ctx.writeResponseError(w, http.StatusInternalServerError, err)
		return
	}

	defer r.Body.Close()
	utils.Debug("%s\n\n", string(body))
	alertmgr.Instance().Send(string(body))
	ctx.writeResponse(w, http.StatusOK, "")
}

func (ctx *WebServer) pingHandler(w http.ResponseWriter, r *http.Request) {
	ctx.writeResponse(w, http.StatusOK, "")
}

func (ctx *WebServer) writeResponse(w http.ResponseWriter, httpStatus int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	if v != nil {
		result, _ := json.Marshal(v)
		w.Write(result)
	}
}

func (ctx *WebServer) writeResponseError(w http.ResponseWriter, httpError int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpError)
	json.NewEncoder(w).Encode(err)
}
