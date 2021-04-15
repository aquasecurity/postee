package webserver

import (
	"log"
	"net/http"
	"os"

	"github.com/aquasecurity/postee/alertmgr"
)

func (web *WebServer) reload(w http.ResponseWriter, r *http.Request) {
	correctKey := os.Getenv("RELOAD_KEY")
	if len(correctKey) == 0 {
		log.Print("reload API key is empty! You need to set an environment variable 'RELOAD_KEY'")
		return
	}
	if key := r.URL.Query().Get("key"); key != correctKey {
		log.Printf("reload API received an incorrect key %q", key)
		return
	}

	log.Printf("----------------------Reconfiguration is starting...----------------------------")
	alertmgr.Instance().ReloadConfig()
}
