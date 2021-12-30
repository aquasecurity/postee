package webserver

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/log"
	"github.com/aquasecurity/postee/router"
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
		correctKey, err := dbservice.Db.GetApiKey()

		if err != nil || correctKey == "" {
			log.Logger.Errorf("reload API key is either empty or there is an error: %s", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}

		if key := r.URL.Query().Get("key"); key != correctKey {
			log.Logger.Errorf("reload API received an incorrect key %q", key)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (ctx *WebServer) Start(host, tlshost string) {
	log.Logger.Info("Starting WebServer....")

	rootDir, _ := utils.GetRootDir()
	certPem := filepath.Join(rootDir, "cert.pem")
	keyPem := filepath.Join(rootDir, "key.pem")

	if ok := utils.PathExists(keyPem); !ok {
		err := utils.GenerateCertificate(keyPem, certPem)
		if err != nil {
			log.Logger.Errorf("GenerateCertificate error: %v", err)
		}
	}

	if os.Getenv("AQUAALERT_CERT_PEM") != "" {
		certPem = os.Getenv("AQUAALERT_CERT_PEM")
	}

	if os.Getenv("AQUAALERT_KEY_PEM") != "" {
		keyPem = os.Getenv("AQUAALERT_KEY_PEM")
	}
	err := dbservice.Db.EnsureApiKey()
	if err != nil {
		log.Logger.Errorf("EnsureApiKey error: %v", err)
	}

	ctx.router.HandleFunc("/", ctx.sessionHandler(ctx.scanHandler)).Methods("POST")
	ctx.router.HandleFunc("/tenant/{route}", ctx.sessionHandler(ctx.tenantHandler)).Methods("POST")
	ctx.router.HandleFunc("/scan", ctx.sessionHandler(ctx.scanHandler)).Methods("POST")
	ctx.router.HandleFunc("/ping", ctx.sessionHandler(ctx.pingHandler)).Methods("GET")

	ctx.router.HandleFunc("/reload", ctx.withApiKey(ctx.reload)).Methods("GET")

	go func() {
		log.Logger.Infof("Listening for HTTP on %s ", host)
		log.Logger.Fatal(http.ListenAndServe(host, ctx.router))
	}()
	go func() {
		log.Logger.Infof("Listening for HTTPS on %s", tlshost)
		log.Logger.Fatal(http.ListenAndServeTLS(tlshost, certPem, keyPem, ctx.router))
	}()
}

func (ctx *WebServer) Terminate() {
	log.Logger.Info("Terminating WebServer....")
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
		log.Logger.Errorf("Failed ioutil.ReadAll: %s", err)
		ctx.writeResponseError(w, http.StatusInternalServerError, err)
		return
	}

	defer r.Body.Close()
	utils.Debug("%s\n\n", string(body))
	router.Instance().Send(body)
	ctx.writeResponse(w, http.StatusOK, "")
}

func (ctx *WebServer) pingHandler(w http.ResponseWriter, r *http.Request) {
	ctx.writeResponse(w, http.StatusOK, "Postee alive!")
}

func (ctx *WebServer) writeResponse(w http.ResponseWriter, httpStatus int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(httpStatus)
	if v != nil {
		result, _ := json.Marshal(v)
		_, err := w.Write(result)
		if err != nil {
			log.Logger.Errorf("Write error: %s", err)
		}
	}
}

func (ctx *WebServer) writeResponseError(w http.ResponseWriter, httpError int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpError)
	errEncode := json.NewEncoder(w).Encode(err)
	if errEncode != nil {
		log.Logger.Errorf("Encode error: %s", errEncode)
	}
}
